# ASI Mini — Technical Documentation

> **CBI AGH · HackNation 2026** — Attack Surface Intelligence engine.
> Single-page dark-mode SOC dashboard, 4 Python files + 1 static UI, Fernet AES
> encryption at rest, 4-role RBAC, DefectDojo integration, Docker-deployable.

---

## 1. Architecture & Design

### 1.1 4‑file modular design

| File | Purpose |
|------|---------|
| `storage.py` | SQLite persistence + Fernet encryption‑at‑rest, seeded 4‑role RBAC, persistent overrides, host stability history, scan jobs |
| `scanner.py` | Target planning/slicing for >10k IP ranges, rate‑limited/time‑windowed live discovery, safe HTTP/TLS/DNS fingerprinting, Nmap/CSV/JSON/manual importers, demo datasets |
| `analyzer.py` | Deterministic risk scoring, MITRE/CVE enrichment, attack‑chain synthesis, override merging, drift detection, CSV/DefectDojo exports |
| `main.py` | FastAPI server, `X‑Auth‑Token` RBAC middleware, auth/users, planning, scans, history, diff, overrides, imports, signatures, exports, DefectDojo push, job scheduling |

All communication between modules is via **plain Python dicts** and **SQLite**. No global state outside `storage.py`; the FastAPI `lifespan` initializer runs `storage.init_db()` once and the background scheduler pulls job state from the same DB.

### 1.2 System architecture diagram

```mermaid
graph TD
    subgraph Frontend
        UI[static/index.html <br/> Tailwind + Cytoscape.js]
        Fetch[fetch() calls <br/> X‑Auth‑Token header]
    end
    subgraph Backend
        MA[main.py <br/> FastAPI + RBAC middleware]
        SL[lifespan scheduler <br/> 15s asyncio tick]
        ST[storage.py <br/> SQLite + Fernet]
        SC[scanner.py <br/> Nmap/TCP/fingerprint]
        AN[analyzer.py <br/> Risk/chain/drift/export]
    end
    direction TB
    UI -- API calls --> MA
    MA -- DB ops --> ST
    MA -- scanning --> SC
    MA -- analysis --> AN
    SC -- raw results --> AN
    AN -- processed --> ST
    ST -- user sessions, roles, jobs --> MA
```

### 1.3 CIDR chunking math ( >10,000 IP planning )

- `plan_targets()` parses raw targets (IP, CIDR, range, domain) via `ipaddress.ip_network`.
- For a `/18` (16,382 hosts): `total_hosts = 2^(32-18) - 2 = 16382`.
- **Optimal chunk size** = `min(window_capacity, 5000, total)` where `window_capacity = int(rps * window_sec)`.
- **Total chunks** = `ceil(total / optimal_chunk)`.
- The UI shows a **`10,000+ IP Ready`** badge when `total >= 10000`.

**Rate‑limit formula**: `interval = 1 / max(rps, 0.1)` seconds between each probe. The `_RateLimiter` class enforces this via `asyncio.sleep`.

### 1.4 Window pause / resume state machine

Each active scan job has `window_start` / `window_end` timestamps. The state machine runs every 15s scheduler tick:

| Condition | Action |
|-----------|--------|
| `now < window_start` | Job stays `pending`; no scans run |
| `window_start <= now <= window_end` | Job runs next chunk; `interval_min` check after each chunk |
| `now > window_end` | Status → `paused_window_expired`; pauses cleanly |
| `paused_window_expired` + new window open | Status reverts to `active`; resumes chunks |

### 1.5 Safe HTTP/HTTPS fingerprinting policy

- **Read‑only passive recon** — `User‑Agent: ASI-Mini/1.0 (read‑only passive recon)`, `verify: false` on TLS, no TCP SYN scans unless `scan_ports=True`.
- **Nmap auto‑use**: `nmap -Pn -sT -sV -oX -` when `scan_ports=True` and `nmap` is on `PATH`; falls back to async TCP prober if nmap unavailable or >64 hosts.
- **No credential submission, no login attempts, no POST requests** to external services. Signatures only match `GET` headers, HTML body, cookies, favicon hash, path status codes.
- **TLS/SSL only** — no active exploit attempts; certificate expiry/validity checked passively.

### 1.6 Flaky‑host heuristics & retry logic

- `host_history` tracks `stability` (`active`/`flaky`/`inactive`), `seen_count`, `scan_count`, `missed_streak`, `time_slots` (hourly buckets).
- During `scan_targets()`, if a host is currently `flaky` and the first probe fails, a **single confirmation retry** is performed after **0.3 s**. The asset record gets `"retried": true`.
- Stability computation (`_compute_stability`):
  - `active`: ratio >= 0.6 and last status `reachable`
  - `flaky`: ratio < 0.6 or missed_streak <= 2 and last status `reachable`
  - `inactive`: missed_streak > 2 or last status `unreachable` with no recent sees

### 1.7 Persistent override merge model

- Analyst notes/tags/severity/status overrides are stored **encrypted** (`enc:` prefix) in `overrides` table.
- On every scan, `analyze_scan()` applies overrides **after** risk scoring but **before** finding finalisation.
- Override fields merge: `custom_severity` overrides the detected severity; `status_override` forces the asset `status`; `notes` and `tags` append/replace per the `_apply_override` logic.
- Manual edits in the UI survive re‑scans because the override key (`asset_key`) is persistent.

### 1.8 Fernet AES Encryption At Rest

- Key derived from `ASI_MASTER_KEY` env var or auto‑generated in `.asi_key`.
- All scan payloads, summaries, and override data are encrypted with `enc:` prefix before writing to SQLite.
- Decryption on‑read; if key rotates, old rows remain encrypted with the old key (back‑compat).

### 1.9 4‑role RBAC permission matrix

| Role | read | modify | add | delete | manage_users | manage_config |
|------|------|--------|-----|--------|--------------|---------------|
| **admin** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **add_delete_modify** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **modify_read** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **read** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

All RBAC checks go through `main.py` middleware (`rbac_middleware`) which reads the user’s `permissions` array from the session table.

### 1.10 DefectDojo API v2 / Generic Findings JSON integration

- `export_defectdojo_json()` produces the **Generic Findings Import** payload.
- Fields: `title`, `description`, `severity`, `mitigation`, `impact`, `references`, `active`, `verified`, `tags`, `date`, `cweid`, `cvssv3_score`, `unique_id_from_tool`, `vuln_id_from_tool`, `component_name`, `component_version`, `service`, `endpoint`.
- Push endpoint: `POST /api/defectdojo/push` → multipart form `file` + `url`, `api_token`, `engagement_id`.
- The payload follows DefectDojo v2 Generic Import format; `minimum_severity` defaults to `Low`, `close_old_findings` = `true`, `deduplication_on_engagement` = `true`.

---

## 2. Quick Start

### 2.1 Local Python

```powershell
# 1. Create venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install deps
.\.venv\Scripts\pip.exe install -r requirements.txt

# 3. Run
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
# Open http://127.0.0.1:8000/
```

### 2.2 One‑command Docker

```powershell
# 1. Build + start with compose
docker compose up --build

# 2. Open http://localhost:8000/
# Data persists in ./data/ volume (asi_data.db + .asi_key)
```

### 2.3 Environment variables

| Var | Default | Description |
|-----|---------|-------------|
| `ASI_DATA_DIR` | `.` (local) / `/app/data` (Docker) | Base dir for `asi_data.db` and `.asi_key` |
| `ASI_DB_PATH` | override DB path | For testing temp files |
| `ASI_KEY_FILE` | `.asi_key` | Override Fernet key file path |
| `ASI_MASTER_KEY` | auto‑gen | 32‑byte Fernet key (base64) — set for reproducible encryption |

---

## 3. API Reference (RBAC‑enforced)

All endpoints require `X‑Auth‑Token` header obtained via `POST /api/login`.

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/api/login` | POST | public | Authenticate & receive token |
| `/api/me` | GET | auth | Return current user |
| `/api/jobs` | GET | read | List all scan jobs |
| `/api/jobs` | POST | add | Create recurring job |
| `/api/jobs/{id}/run-now` | POST | modify or add | Run next chunk immediately |
| `/api/jobs/{id}` | DELETE | delete | Delete a job |
| `/api/plan` | POST | read | CIDR planning |
| `/api/scan` | POST | add or modify | Run live or demo scan |
| `/api/scans` | GET | read | List saved scans |
| `/api/scans/{id}` | GET | read | Get scan detail |
| `/api/scans/{id}` | DELETE | delete | Delete scan |
| `/api/diff` | GET | read | Scan‑to‑scan drift |
| `/api/overrides` | GET | read | List overrides |
| `/api/overrides` | POST | modify | Save persistent override |
| `/api/signatures` | GET | read | List signatures |
| `/api/signatures` | POST | add | Add custom signature |
| `/api/signatures/{id}` | DELETE | delete | Delete signature |
| `/api/export/{id}?fmt=json` | GET | read | JSON export |
| `/api/export/{id}?fmt=csv` | GET | read | CSV export |
| `/api/export/{id}?fmt=defectdojo` | GET | read | DefectDojo JSON |
| `/api/defectdojo/push` | POST | modify | Push to DefectDojo |
| `/api/host-history` | GET | read | Host stability history |

---

## 4. Verification

### 4.1 py_compile

```powershell
.\.venv\Scripts\python.exe -m py_compile storage.py scanner.py analyzer.py main.py
# → COMPILE OK
```

### 4.2 TestClient suite (old + new checks)

All **24** previous checks still pass:

- (a) All 4 roles log in
- (b) Auditor gets 403 on write endpoints
- (c) `10.0.0.0/18` plan → 16382 hosts, `supports_10k_scale=True`
- (d) demo1/demo2 encrypted rows, diff, persistent overrides
- (e) DefectDojo + CSV exports

**New checks (must also pass):**

- Creating a recurring job (`10.0.0.0/18`, window `00:00`‑`23:59`, interval `30`) → **200**
- `POST /api/jobs/{id}/run-now` advances `cursor_index` and saves an encrypted scan
- `auditor` gets **403** on `POST /api/jobs` and `DELETE /api/jobs/{id}`
- `GET /` returns **200** and every `/api/...` call in `static/index.html` matches an existing route in `main.py`

### 4.3 Smoke suite

All **24** smoke checks pass (imports, users/roles, signatures CRUD, scan jobs, host history, live localhost scan, window pause, delete scan).

---

## 5. Deployment Checklist

- [ ] `Dockerfile` builds `python:3.13-slim` with `nmap + ca-certificates`
- [ ] `docker-compose.yml` maps `8000:8000` and mounts `./data:/app/data`
- [ ] `.dockerignore` excludes `.venv`, `*.db`, `.asi_key`, `.git`, `__pycache__`, `opencode.json`, `AGENTS.md`, `GEMINI.md`
- [ ] `.gitignore` includes `data/`
- [ ] `ASI_DATA_DIR=/app/data` set in compose env
- [ ] `requirements.txt` pinned (fastapi, uvicorn, httpx, dnspython, cryptography)
- [ ] `docs/TECHNICAL.md` created with architecture, CIDR math, rate‑limit, window PBS, fingerprinting policy, Fernet AES, 4‑role RBAC, DefectDojo guide
- [ ] `README.md` updated with 1‑command Docker launch + link to `docs/TECHNICAL.md`
- [ ] All `py_compile` checks pass
- [ ] TestClient suite: 24/24 PASS (old) + new job checks
- [ ] Frontend: every `fetch()` call uses `X‑Auth‑Token`; no hardcoded admin fallback