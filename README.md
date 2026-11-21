# ASI Mini — Attack Surface Intelligence (HackNation 2026 / CBI AGH)

Lightweight, zero-bloat Attack Surface Intelligence engine that uncovers external and internal infrastructure blind spots before attackers exploit them.

## Key Capabilities
- **Passive External Recon:** Discovers subdomains via Certificate Transparency (`crt.sh`), inspects DNS (`A`, `CNAME`, `MX`, `SPF`, `DMARC`), checks TLS certificate health/expiry, and audits HTTP headers/banners.
- **Internal Network Ingestion:** Parses standard `Nmap XML` scan files to flag high-risk open ports (`Telnet`, `SMB`, `RDP`, `Redis`, `MongoDB`, `PostgreSQL`, `FTP`, `Elasticsearch`).
- **Deterministic Risk Engine:** Transparent 0–100 exposure score (Grade A–F), severity ranking (`CRITICAL` → `LOW`), concrete evidence, attack vectors, and actionable remediation steps.
- **Interactive Attack-Path Graph:** Real-time Cytoscape.js graph mapping `Target → Assets → Critical/High Blind Spots` with click-to-filter triage and 1-click JSON export.
- **Offline-Resilient Demo Mode:** Built-in external and internal sample datasets for reliable demonstrations without external network dependency.

## Architecture (4 Files)
- `main.py` — FastAPI server (`/`, `/api/health`, `/api/scan`, `/api/import`)
- `scanner.py` — Async passive OSINT collector & stdlib Nmap XML parser
- `analyzer.py` — Deterministic blind-spot detector, exposure scorer & graph builder
- `static/index.html` — Single-page dark-mode SOC dashboard (Tailwind + Cytoscape.js)

## Quick Start
```bash
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload