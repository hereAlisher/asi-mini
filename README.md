# ASI Mini — Attack Surface Intelligence (HackNation 2026 / CBI AGH)

Lightweight, zero-bloat Attack Surface Intelligence engine that uncovers external and internal infrastructure blind spots before attackers exploit them.

## ⚡ Quickstart (1-Command Docker)

```powershell
docker compose up --build -d
```

- **Dashboard:** [http://localhost:8000](http://localhost:8000)
- **Healthcheck:** [http://localhost:8000/api/health](http://localhost:8000/api/health)
- **Data Persistence:** Stored in `./data/` volume (`asi_data.db` + `.asi_key`).
- **Docker-to-Host Scanning:** Point scans to `host.docker.internal` to scan services on your host machine.

## 🛡️ Default RBAC Accounts

| Role | Username / Password | Permissions | Role Label / Scope |
|---|---|---|---|
| `admin` | `admin` / `admin123` | `read`, `modify`, `add`, `delete`, `manage_users`, `manage_config` | Administracja (Full SOC control) |
| `operator` | `operator` / `operator123` | `read`, `modify` | Modyfikacja i odczyt (Triage & ops) |
| `analyst` | `analyst` / `analyst123` | `read`, `modify`, `add`, `delete` | Dodawanie, usuwanie, modyfikacja (Scans & overrides) |
| `auditor` | `auditor` / `auditor123` | `read` | Odczyt (Read-only compliance audit) |

*Authenticate via `POST /api/login` and pass the returned token in the `X-Auth-Token` header.*

## 🎯 Evaluation Lab Port Presets

Tab 2 includes one-click preset chips for targeted evaluation and testing:

| Preset | Target Ports | Evaluated Environment & Scenarios |
|---|---|---|
| **Quickstart Drift** | `2223,3001,5673,8787,15673` | Drift detection across SSH, web services, AMQP & RabbitMQ |
| **Proxy / Latency** | `8085,8086,8474` | Traefik, Toxiproxy, timeout tolerances & response latency (ms) |
| **Vulnerable Stack** | `21,8088,8089,8090` | FTP, DVWA, legacy web interfaces & unauthenticated admin portals |
| **Modern Stack** | `80,81,443,6379,8080,8081` | HTTP/S, Nginx Proxy Manager, Redis cache & cloud microservices |
| **10k+ CIDR Plan** | *(target: `10.0.0.0/18`)* | Lazy CIDR arithmetic slicing 16,382 hosts without RAM expansion |

## 🏗️ Architecture Highlights

- **4-File FastAPI Backend:** Ultra-small, maintainable codebase (`main.py`, `storage.py`, `scanner.py`, `analyzer.py`) paired with a single-file static dashboard (`static/index.html` via Tailwind & Cytoscape CDN).
- **SQLite + Fernet AES At Rest:** Scan payloads, summaries, analyst notes, and tags stored with `enc:` Fernet AES encryption in SQLite. Key auto-generated in `.asi_key` or supplied via `ASI_MASTER_KEY`.
- **Lazy >10k IP CIDR Batching:** Arithmetic slicing using Python stdlib `ipaddress` handles large address spaces (`10.0.0.0/18` = 16,382 hosts) safely without expanding addresses into memory.
- **DefectDojo API v2 Selective Export:** Direct export and push to DefectDojo Generic Findings Import API with per-finding evidence toggle.
- **Zero GPL Dependencies:** Exclusively MIT, BSD, Apache-2.0, and Python stdlib for clean AGH IP transfer compliance.
- **91+ Automated Tests:** Comprehensive test coverage across RBAC 403 enforcement, persistent overrides, drift detection, signature matching, and flaky-host stability tracking.

## Key Capabilities
- **10k+ Scale Planning:** Lazy CIDR arithmetic (`ipaddress`) slices `10.0.0.0/18` (16,382 hosts) into rate-limited, resumable chunks without expanding every IP into memory.
- **Safe Passive + Active Discovery:** DNS (`A`, `CNAME`, `MX`, `SPF`, `DMARC`), TLS certificate health/expiry, optional async TCP checks or Nmap subprocess fallback, and read-only HTTP/HTTPS fingerprinting (title, status, headers, cookies, redirects, favicon SHA-256, CMS/framework/IoT technologies).
- **Safe Read-Only Signatures:** 10 seeded signatures covering CMS, cookies, headers, `/admin`, `/login`, `/version`, staging and IoT. Only GET requests — never credentials, POSTs or login attempts.
- **Risk Engine:** Risky ports, dangling CNAME takeovers, invalid/expiring TLS, plaintext HTTP, exposed admin/staging surfaces, CVE/legacy banners, missing security headers, missing SPF/DMARC and every signature hit. Findings carry MITRE ATT&CK IDs, CVE, stable fingerprints and attack-chain synthesis.
- **Scan-to-Scan Drift:** New/removed assets, changed services, new/resolved findings, score delta and flaky/offline host tracking across runs.
- **Encryption At Rest:** Fernet-encrypted scan payloads, summaries, target lists, analyst notes and tags (`enc:` prefix) in SQLite. Key auto-generated in `.asi_key` or supplied via `ASI_MASTER_KEY`.
- **4-Role RBAC + Custom Roles:** `admin`, `add_delete_modify`, `modify_read`, `read`, with persistent manual overrides that survive future re-scans.
- **Unified Ingestion:** Manual, CSV, JSON and Nmap XML imports produce the same schema as live scans.
- **Exports:** JSON, CSV and DefectDojo Generic Findings Import JSON, plus direct DefectDojo push.

## Local Quick Start (Without Docker)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
.\.venv\Scripts\pip.exe install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/`.

Link to full technical documentation: [docs/TECHNICAL.md](docs/TECHNICAL.md)

## Key Endpoints
- Auth: `GET /api/health`, `POST /api/login`, `GET /api/me`, `GET/POST /api/users`, `GET/POST /api/roles`
- Planning/scanning: `POST /api/plan`, `POST /api/scan`, `GET /api/scan`
- History/drift/edits: `GET /api/scans`, `GET/DELETE /api/scans/{id}`, `GET /api/diff`, `GET/POST /api/overrides`
- Imports/signatures: `POST /api/import`, `GET/POST /api/signatures`, `DELETE /api/signatures/{id}`
- Exports: `GET /api/export/{id}?fmt=json|csv|defectdojo`, `POST /api/defectdojo/push`

## Verification
```powershell
.\.venv\Scripts\python.exe -m py_compile storage.py scanner.py analyzer.py main.py
```

All **24** previous checks still pass, plus new checks:

- Creating a recurring job (`10.0.0.0/18`, window `00:00`-`23:59`, interval `30`) -> **200**
- `POST /api/jobs/{id}/run-now` advances `cursor_index` and saves an encrypted scan
- `auditor` gets **403** on `POST /api/jobs` and `DELETE /api/jobs/{id}`
- `GET /` returns **200** and every `/api/...` call in `static/index.html` matches an existing route in `main.py`

The included test flow verifies all four roles, 403 enforcement for read-only users, `10.0.0.0/18` planning (16,382 hosts), encrypted SQLite rows, demo1/demo2 drift (new WordPress+Redis host and flaky offline host), persistent overrides on a third scan, and DefectDojo/CSV exports.

## Lab Target Simulator

For live jury demos, launch 3 local HTTP servers (stdlib-only, no deps):

```powershell
.\.venv\Scripts\python.exe lab_sim.py
```

| Port | Service | Purpose |
|------|---------|---------|
| 9001 | LabCMS (WordPress) | CMS fingerprint, PHPSESSID cookie, /admin 200, footer version |
| 9002 | Staging API (Werkzeug) | Staging hostname detection, /version endpoint |
| 9003 | Flaky IoT (Cisco-ASA) | Alternates 200/503 to prove flaky-host detection |

Press `Ctrl+C` to stop all servers.
