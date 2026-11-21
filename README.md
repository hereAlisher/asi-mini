# ASI Mini — Attack Surface Intelligence (HackNation 2026 / CBI AGH)

Lightweight, zero-bloat Attack Surface Intelligence engine that uncovers external and internal infrastructure blind spots before attackers exploit them.

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

## Architecture (4 Python Files + 1 Static UI)
- `main.py` — FastAPI server, `X-Auth-Token` RBAC middleware, auth/users, planning, scans, history, diff, overrides, imports, signatures, exports and DefectDojo push.
- `storage.py` — SQLite schema, Fernet encryption, sessions, seeded RBAC, persistent overrides, host stability history and scan jobs.
- `scanner.py` — target planning/slicing, rate limiting, time windows, DNS/TLS/TCP/HTTP fingerprinting, signature matching, importers and demo datasets.
- `analyzer.py` — risk scoring, MITRE/CVE enrichment, attack chains, override merging, drift and exports.
- `static/index.html` — single-page dark-mode SOC dashboard (Tailwind + Cytoscape.js CDN, no build step).

## Default Accounts
| Role key | Role label | Login | Permissions |
|---|---|---|---|
| `admin` | Administracja | `admin` / `admin123` | `read`, `modify`, `add`, `delete`, `manage_users`, `manage_config` |
| `add_delete_modify` | Dodawanie, usuwanie, modyfikacja | `analyst` / `analyst123` | `read`, `modify`, `add`, `delete` |
| `modify_read` | Modyfikacja i odczyt | `operator` / `operator123` | `read`, `modify` |
| `read` | Odczyt | `auditor` / `auditor123` | `read` |

Authenticate with `POST /api/login` and send the returned token as `X-Auth-Token`.

## Quick Start
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
.\.venv\Scripts\pip.exe install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/`.

## Key Endpoints
- Auth: `POST /api/login`, `GET /api/me`, `GET/POST /api/users`, `GET/POST /api/roles`
- Planning/scanning: `POST /api/plan`, `POST /api/scan`, `GET /api/scan`
- History/drift/edits: `GET /api/scans`, `GET/DELETE /api/scans/{id}`, `GET /api/diff`, `GET/POST /api/overrides`
- Imports/signatures: `POST /api/import`, `GET/POST /api/signatures`, `DELETE /api/signatures/{id}`
- Exports: `GET /api/export/{id}?fmt=json|csv|defectdojo`, `POST /api/defectdojo/push`

## Verification
```powershell
.\.venv\Scripts\python.exe -m py_compile storage.py scanner.py analyzer.py main.py
```

The included test flow verifies all four roles, 403 enforcement for read-only users, `10.0.0.0/18` planning (16,382 hosts), encrypted SQLite rows, demo1/demo2 drift (new WordPress+Redis host and flaky offline host), persistent overrides on a third scan, and DefectDojo/CSV exports.
