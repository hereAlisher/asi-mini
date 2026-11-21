import re

SENSITIVE_PREFIXES = ("admin", "dev", "staging", "stage", "test", "vpn", "api", "internal", "jenkins", "git", "beta")
TAKEOVER_TARGETS = ("azurewebsites.net", "herokuapp.com", "github.io", "s3.amazonaws.com", "cloudfront.net", "netlify.app", "vercel.app", "pantheonsite.io")
SEV_WEIGHT = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 4}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

RISKY_PORTS = {
    23: ("CRITICAL", "Exposed Telnet (Port 23)", "Cleartext remote administration allows credential sniffing and takeover.", "Disable Telnet immediately and migrate to key-based SSH."),
    445: ("CRITICAL", "Exposed SMB Service (Port 445)", "Primary ransomware propagation and lateral-movement vector.", "Block TCP/445 at perimeter/VLAN boundaries and restrict SMB access."),
    3389: ("CRITICAL", "Exposed RDP Service (Port 3389)", "High-value target for credential stuffing, brute-force, and RCE.", "Place RDP behind VPN/bastion host with MFA and NLA enabled."),
    6379: ("CRITICAL", "Exposed Redis Datastore (Port 6379)", "Frequently unauthenticated; permits full data dump or remote code execution.", "Bind Redis to localhost, require ACL authentication, and firewall TCP/6379."),
    27017: ("CRITICAL", "Exposed MongoDB Port (Port 27017)", "Direct NoSQL access risks mass data exfiltration or ransom wipe.", "Enable database auth, bind internally, and restrict TCP/27017."),
    9200: ("CRITICAL", "Exposed Elasticsearch API (Port 9200)", "Unprotected REST API leaks indexed logs and internal telemetry.", "Restrict to internal subnet with TLS and role-based authentication."),
    21: ("HIGH", "Exposed Cleartext FTP (Port 21)", "Credentials and transferred artifacts travel unencrypted.", "Decommission FTP in favor of SFTP/FTPS and close TCP/21."),
    3306: ("HIGH", "Exposed MySQL Database (Port 3306)", "Direct DB network reachability expands lateral-movement blast radius.", "Restrict TCP/3306 strictly to authorized application servers."),
    5432: ("HIGH", "Exposed PostgreSQL Database (Port 5432)", "Direct DB exposure invites credential brute-force and privilege escalation.", "Enforce pg_hba.conf IP allowlists and segment database VLAN."),
    8080: ("MEDIUM", "Alternate HTTP / CI Service (Port 8080)", "Commonly exposes unhardened Jenkins, debug consoles, or admin UIs.", "Audit service on 8080, enforce SSO/TLS, or disable external access."),
    22: ("LOW", "Exposed SSH Service (Port 22)", "Continuous brute-force surface if password auth or legacy versions remain active.", "Disable password/root login, enforce SSH keys, and restrict source IPs."),
}


def _finding(sev: str, cat: str, host: str, title: str, evidence: str, vector: str, fix: str) -> dict:
    return {
        "severity": sev,
        "category": cat,
        "host": host,
        "title": title,
        "evidence": evidence,
        "attack_vector": vector,
        "remediation": fix,
    }


def _score_to_level(score: int) -> str:
    if score >= 60:
        return "CRITICAL"
    if score >= 35:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"


def analyze_scan(scan: dict) -> dict:
    target = scan["target"]
    dns_root = scan.get("dns_root", {})
    subdomains = scan.get("subdomains", [])
    findings: list[dict] = []
    host_scores: dict[str, int] = {}

    if not dns_root.get("has_dmarc"):
        findings.append(_finding(
            "MEDIUM", "DNS / Email", target,
            "Missing DMARC Policy",
            f"No _dmarc.{target} TXT record found.",
            "Attackers can spoof organizational emails for spear-phishing.",
            f"Publish a TXT record at _dmarc.{target}: v=DMARC1; p=quarantine; rua=mailto:sec@{target}",
        ))
    if not dns_root.get("has_spf"):
        findings.append(_finding(
            "MEDIUM", "DNS / Email", target,
            "Missing SPF Record",
            f"No v=spf1 TXT record on {target}.",
            "Unauthorized mail servers can send emails pretending to be your domain.",
            "Add a strict SPF TXT record authorizing only legitimate mail relays.",
        ))

    for sub in subdomains:
        host = sub["host"]
        http = sub.get("http", {})
        tls = sub.get("tls", {})
        ips = sub.get("ips", [])
        cnames = sub.get("cnames", [])
        open_ports = sub.get("open_ports", [])
        prefix = host.split(".")[0] if host != target else ""
        is_sensitive = any(k in prefix for k in SENSITIVE_PREFIXES)
        h_findings: list[dict] = []

        # Internal / Network open-port checks (from Nmap XML)
        for p in open_ports:
            port_num = p.get("port")
            if port_num in RISKY_PORTS:
                sev, title, vector, fix = RISKY_PORTS[port_num]
                banner = " ".join(x for x in (p.get("service"), p.get("product"), p.get("version")) if x).strip()
                h_findings.append(_finding(
                    sev, "Network / Port Exposure", host, title,
                    f"TCP/{port_num} open on {', '.join(ips) or host} ({banner or 'detected'}).",
                    vector, fix,
                ))

        # Dangling CNAME / Subdomain Takeover
        for cname in cnames:
            c_low = cname.lower().rstrip(".")
            if any(p in c_low for p in TAKEOVER_TARGETS) and (not ips or not http.get("reachable")):
                h_findings.append(_finding(
                    "CRITICAL", "Subdomain Takeover", host,
                    "Dangling Cloud CNAME Detected",
                    f"CNAME -> {c_low} (unreachable / unresolved target).",
                    "Attacker registers the abandoned cloud resource and hosts phishing/XSS under your trusted domain.",
                    f"Immediately remove the orphaned DNS CNAME record for {host} or reclaim {c_low}.",
                ))

        # TLS health
        if tls.get("valid") is False:
            h_findings.append(_finding(
                "CRITICAL" if is_sensitive else "HIGH", "TLS / Encryption", host,
                "Invalid TLS Certificate",
                f"TLS verification failed: {tls.get('error')}",
                "Enables MitM interception and signals unmanaged shadow infrastructure.",
                f"Replace with a valid CA-signed certificate or restrict {host} behind internal VPN.",
            ))
        elif tls.get("days_remaining") is not None and tls["days_remaining"] <= 14:
            h_findings.append(_finding(
                "HIGH", "TLS / Expiry", host,
                f"TLS Certificate Expiring in {tls['days_remaining']} Days",
                f"Issuer: {tls.get('issuer')} | {tls['days_remaining']} days left.",
                "Imminent service outage or user habituation to bypassing browser cert warnings.",
                "Automate certificate renewal (ACME / certbot) and enable expiry alerting at 30 days.",
            ))

        # Plaintext HTTP
        url = http.get("url") or ""
        if http.get("reachable") and url.startswith("http://"):
            h_findings.append(_finding(
                "CRITICAL" if is_sensitive else "HIGH", "Unencrypted Transport", host,
                "Service Exposed Over Plaintext HTTP",
                f"Reachable at {url} (HTTP {http.get('status')}).",
                "Credentials, session cookies, and API tokens transmitted in cleartext.",
                "Enforce HTTPS with 301 redirect and enable Strict-Transport-Security (HSTS).",
            ))

        # Publicly reachable sensitive/shadow surface
        if is_sensitive and http.get("reachable"):
            h_findings.append(_finding(
                "HIGH", "Shadow / Admin Exposure", host,
                f"Publicly Reachable Sensitive Surface ({prefix})",
                f"HTTP {http.get('status')} at {url} on IP {', '.join(ips) or 'N/A'}.",
                "Prime target for credential stuffing, debug-interface abuse, and unpatched exploits.",
                f"Restrict {host} via IP allowlist, Zero-Trust proxy, or internal VPN; disable public routing.",
            ))

        # Version leaks
        banners = [b for b in (http.get("server"), http.get("x_powered_by")) if b]
        version_leaks = [b for b in banners if re.search(r"/\d+\.\d+", b)]
        if version_leaks:
            h_findings.append(_finding(
                "HIGH" if any(x in " ".join(version_leaks).lower() for x in ("werkzeug", "php/7", "2.4.49")) else "MEDIUM",
                "Fingerprinting / Legacy Stack", host,
                "Detailed Software Version Exposed",
                f"Headers leak: {', '.join(version_leaks)}",
                "Accelerates attacker CVE matching and automated exploit targeting.",
                "Upgrade legacy runtimes, suppress Server/X-Powered-By headers, and never run dev servers in prod.",
            ))

        # Missing headers
        missing = http.get("missing_headers", [])
        if http.get("reachable") and len(missing) >= 2:
            h_findings.append(_finding(
                "MEDIUM" if len(missing) >= 3 else "LOW",
                "HTTP Hardening", host,
                f"Missing {len(missing)} Security Headers",
                f"Missing: {', '.join(missing)}",
                "Increases exposure to clickjacking, MIME sniffing, XSS, and SSL stripping.",
                "Configure HSTS, CSP, X-Frame-Options, and X-Content-Type-Options on reverse proxy.",
            ))

        h_score = min(100, sum(SEV_WEIGHT[f["severity"]] for f in h_findings))
        host_scores[host] = h_score
        findings.extend(h_findings)

    findings.sort(key=lambda f: (SEV_RANK[f["severity"]], f["host"]))
    for idx, f in enumerate(findings, 1):
        f["id"] = f"ASI-{idx:03d}"

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    overall = min(100, counts["CRITICAL"] * 25 + counts["HIGH"] * 14 + counts["MEDIUM"] * 6 + counts["LOW"] * 2)
    grade = "F" if overall >= 75 else "D" if overall >= 55 else "C" if overall >= 35 else "B" if overall >= 15 else "A"

    nodes = [{"data": {"id": f"root:{target}", "label": target, "type": "root", "severity": _score_to_level(overall), "score": overall}}]
    edges = []

    for sub in subdomains:
        h = sub["host"]
        sc = host_scores.get(h, 0)
        sev = _score_to_level(sc)
        if h != target:
            nodes.append({"data": {"id": f"host:{h}", "label": h, "type": "host", "severity": sev, "score": sc, "ips": ", ".join(sub.get("ips", []))}})
            edges.append({"data": {"source": f"root:{target}", "target": f"host:{h}", "label": "asset"}})
        for c in sub.get("cnames", []):
            cid = f"cname:{c}"
            nodes.append({"data": {"id": cid, "label": c.rstrip("."), "type": "external", "severity": "CRITICAL" if sc >= 30 else "LOW"}})
            edges.append({"data": {"source": f"host:{h}" if h != target else f"root:{target}", "target": cid, "label": "CNAME"}})

    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH"):
            fid = f"find:{f['id']}"
            src = f"root:{target}" if f["host"] == target else f"host:{f['host']}"
            nodes.append({"data": {"id": fid, "label": f["title"], "type": "finding", "severity": f["severity"], "finding_id": f["id"]}})
            edges.append({"data": {"source": src, "target": fid, "label": f["severity"]}})

    return {
        "summary": {
            "exposure_score": overall,
            "grade": grade,
            "risk_level": _score_to_level(overall),
            "assets_discovered": len(subdomains),
            "findings_total": len(findings),
            "severity_counts": counts,
        },
        "host_scores": host_scores,
        "findings": findings,
        "graph": {"nodes": nodes, "edges": edges},
    }