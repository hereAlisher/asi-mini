"""ASI Mini analysis engine.

Deterministic risk scoring, MITRE/CVE enrichment, attack-chain synthesis,
persistent override merging, host stability attribution, scan-to-scan drift
and DefectDojo/CSV exports.
"""
from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from typing import Any

SEV_WEIGHT = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 1}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SUPPRESSED_STATUSES = {"false_positive", "resolved", "accepted_risk", "suppressed", "closed"}

SENSITIVE_PREFIXES = ("admin", "dev", "staging", "stage", "test", "vpn", "api", "internal",
                      "jenkins", "git", "beta", "shop", "legacy")
TAKEOVER_TARGETS = ("azurewebsites.net", "herokuapp.com", "github.io", "s3.amazonaws.com",
                    "cloudfront.net", "netlify.app", "vercel.app", "pantheonsite.io",
                    "trafficmanager.net", "cloudapp.azure.com", "elasticbeanstalk.com")

RISKY_PORTS = {
    23: ("CRITICAL", "Exposed Telnet (Port 23)", "Cleartext remote administration allows credential sniffing and takeover.", "Disable Telnet immediately and migrate to key-based SSH."),
    445: ("CRITICAL", "Exposed SMB Service (Port 445)", "Primary ransomware propagation and lateral-movement vector.", "Block TCP/445 at perimeter/VLAN boundaries and restrict SMB access."),
    3389: ("CRITICAL", "Exposed RDP Service (Port 3389)", "High-value target for credential stuffing, brute-force, and RCE.", "Place RDP behind VPN/bastion host with MFA and NLA enabled."),
    6379: ("CRITICAL", "Exposed Redis Datastore (Port 6379)", "Frequently unauthenticated; permits full data dump or remote code execution.", "Bind Redis to localhost, require ACL authentication, and firewall TCP/6379."),
    27017: ("CRITICAL", "Exposed MongoDB Port (Port 27017)", "Direct NoSQL access risks mass data exfiltration or ransom wipe.", "Enable database auth, bind internally, and restrict TCP/27017."),
    9200: ("CRITICAL", "Exposed Elasticsearch API (Port 9200)", "Unprotected REST API leaks indexed logs and internal telemetry.", "Restrict to internal subnet with TLS and role-based authentication."),
    2375: ("CRITICAL", "Unauthenticated Docker API (Port 2375)", "Remote Docker control grants host-level root code execution.", "Disable the TCP socket and require TLS client certificates."),
    11211: ("HIGH", "Exposed Memcached (Port 11211)", "Unauthenticated cache access leaks sessions and enables amplification abuse.", "Bind to localhost and firewall UDP/TCP 11211."),
    5900: ("HIGH", "Exposed VNC Service (Port 5900)", "Remote desktop without network isolation invites brute-force takeover.", "Tunnel VNC over SSH/VPN and enforce strong authentication."),
    21: ("HIGH", "Exposed Cleartext FTP (Port 21)", "Credentials and transferred artifacts travel unencrypted.", "Decommission FTP in favor of SFTP/FTPS and close TCP/21."),
    3306: ("HIGH", "Exposed MySQL Database (Port 3306)", "Direct DB network reachability expands lateral-movement blast radius.", "Restrict TCP/3306 strictly to authorized application servers."),
    5432: ("HIGH", "Exposed PostgreSQL Database (Port 5432)", "Direct DB exposure invites credential brute-force and privilege escalation.", "Enforce pg_hba.conf IP allowlists and segment database VLAN."),
    1433: ("HIGH", "Exposed Microsoft SQL Server (Port 1433)", "Direct database exposure invites brute-force and xp_cmdshell abuse.", "Restrict TCP/1433 to application subnets and enforce strong auth."),
    15672: ("HIGH", "Exposed RabbitMQ Management (Port 15672)", "Management UI often ships with default credentials.", "Restrict the management plugin to localhost or an admin VLAN."),
    8080: ("MEDIUM", "Alternate HTTP / CI Service (Port 8080)", "Commonly exposes unhardened Jenkins, debug consoles, or admin UIs.", "Audit service on 8080, enforce SSO/TLS, or disable external access."),
    22: ("LOW", "Exposed SSH Service (Port 22)", "Continuous brute-force surface if password auth or legacy versions remain active.", "Disable password/root login, enforce SSH keys, and restrict source IPs."),
}

CVE_RULES: list[tuple[str, str]] = [
    (r"apache/2\.4\.49", "CVE-2021-41773"),
    (r"apache/2\.4\.50", "CVE-2021-42013"),
    (r"php/7\.4\.[0-9]", "CVE-2019-11043"),
    (r"php/5\.", "CVE-2019-11043"),
    (r"werkzeug", "CVE-2024-34069"),
    (r"openssh[_ ]7\.9", "CVE-2018-15473"),
    (r"cisco[- ]asa", "CVE-2020-3187"),
    (r"redis.*6\.", "CVE-2022-0543"),
    (r"jenkins", "CVE-2024-23897"),
    (r"jetty/9\.4", "CVE-2023-36478"),
    (r"iis/10\.0", "CVE-2022-21907"),
    (r"wordpress.*5\.", "CVE-2022-21661"),
    (r"log4j", "CVE-2021-44228"),
]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

MITRE_BY_CATEGORY = {
    "Network / Port Exposure": ("T1133", "Initial Access"),
    "Subdomain Takeover": ("T1584.001", "Resource Development"),
    "TLS / Encryption": ("T1557", "Credential Access"),
    "TLS / Expiry": ("T1557", "Credential Access"),
    "Unencrypted Transport": ("T1040", "Credential Access"),
    "Shadow / Admin Exposure": ("T1078", "Initial Access"),
    "Fingerprinting / Legacy Stack": ("T1592", "Reconnaissance"),
    "HTTP Hardening": ("T1185", "Collection"),
    "DNS / Email": ("T1566", "Initial Access"),
    "CVE / Legacy Service": ("T1190", "Initial Access"),
    "Signature Match": ("T1595", "Reconnaissance"),
    "CMS / Web Platform": ("T1190", "Initial Access"),
    "Framework / Runtime": ("T1592", "Reconnaissance"),
    "Application Server": ("T1592", "Reconnaissance"),
    "IoT / Network Appliance": ("T1190", "Initial Access"),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(category: str, host: str, title: str) -> str:
    return hashlib.sha256(f"{category}|{host}|{title}".lower().encode("utf-8")).hexdigest()[:12]


def _detect_cve(text: str) -> str | None:
    found = CVE_RE.search(text or "")
    if found:
        return found.group(0).upper()
    lowered = (text or "").lower()
    for pattern, cve in CVE_RULES:
        if re.search(pattern, lowered):
            return cve
    return None


def _finding(sev: str, category: str, host: str, title: str, evidence: str, vector: str,
             fix: str, *, mitre_id: str | None = None, mitre_tactic: str | None = None,
             cve: str | None = None, source: str = "engine", extra: dict | None = None) -> dict:
    default_mitre, default_tactic = MITRE_BY_CATEGORY.get(category, ("T1595", "Reconnaissance"))
    fp = _fingerprint(category, host, title)
    item = {
        "id": f"ASI-{fp[:6].upper()}",
        "severity": sev.upper(),
        "category": category,
        "host": host,
        "title": title,
        "evidence": evidence,
        "attack_vector": vector,
        "remediation": fix,
        "mitre_id": mitre_id or default_mitre,
        "mitre_tactic": mitre_tactic or default_tactic,
        "cve": (cve or _detect_cve(evidence) or "").upper() or None,
        "fingerprint": fp,
        "source": source,
        "status": "open",
        "notes": "",
        "tags": [],
        "custom_severity": None,
        "status_override": None,
    }
    if extra:
        item.update(extra)
    return item


def _score_to_level(score: int) -> str:
    if score >= 60:
        return "CRITICAL"
    if score >= 35:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"


def _override_index(overrides: Any) -> dict[str, dict]:
    if not overrides:
        return {}
    items = overrides.items() if isinstance(overrides, dict) else [
        (str(o.get("asset_key")), o) for o in overrides if isinstance(o, dict)
    ]
    index: dict[str, dict] = {}
    for key, value in items:
        if not key or not isinstance(value, dict):
            continue
        low = str(key).strip().lower()
        index[low] = value
        if low.startswith("host:"):
            index[low[5:]] = value
        elif low.startswith("finding:"):
            index[low[8:]] = value
    return index


def _lookup_override(index: dict[str, dict], keys: list[str]) -> dict | None:
    for key in keys:
        if key and key.lower() in index:
            return index[key.lower()]
    return None


def _apply_override(target: dict, override: dict, *, kind: str) -> None:
    if not override:
        return
    if override.get("notes") is not None:
        target["notes"] = override.get("notes") or ""
    if override.get("tags") is not None:
        target["tags"] = override.get("tags") or []
    if override.get("status_override"):
        target["status_override"] = override["status_override"]
        target["status"] = override["status_override"]
    if override.get("custom_severity"):
        target["custom_severity"] = override["custom_severity"]
        if kind == "finding":
            target["severity"] = override["custom_severity"]
    target["overridden"] = True
    target["override_updated_by"] = override.get("updated_by")
    target["override_updated_at"] = override.get("updated_at")


def _asset_reachable(asset: dict) -> bool:
    http = asset.get("http") or {}
    tls = asset.get("tls") or {}
    return bool(http.get("reachable") or asset.get("open_ports") or tls.get("valid") is True)


def _host_override_keys(host: str) -> list[str]:
    low = host.lower()
    return [low, f"host:{low}"]


def _finding_override_keys(finding: dict) -> list[str]:
    fp = str(finding.get("fingerprint") or "").lower()
    fid = str(finding.get("id") or "").lower()
    host = str(finding.get("host") or "").lower()
    return [fp, f"finding:{fp}", fid, f"finding:{fid}", f"{host}:{fp}", f"host:{host}:{fp}"]


def _signature_findings(asset: dict, host: str) -> list[dict]:
    http = asset.get("http") or {}
    signatures = list(http.get("matched_signatures") or []) + list(asset.get("matched_signatures") or [])
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for sig in signatures:
        if not isinstance(sig, dict):
            continue
        name = str(sig.get("name") or "Signature Match")
        evidence = str(sig.get("evidence") or f"Signature '{name}' matched on {host}")
        marker = (name, evidence)
        if marker in seen:
            continue
        seen.add(marker)
        category = str(sig.get("category") or "Signature Match")
        severity = str(sig.get("severity") or "MEDIUM").upper()
        out.append(_finding(
            severity, category, host, name, evidence,
            sig.get("description") or "Matched a read-only fingerprint signature that exposes the asset technology or interface.",
            sig.get("remediation") or "Reduce the exposed fingerprint, patch the component and restrict public access.",
            mitre_id=sig.get("mitre_id"), cve=sig.get("cve"), source="signature",
            extra={"signature_id": sig.get("signature_id"), "match_type": sig.get("match_type")},
        ))
    return out


def _build_chains(findings: list[dict], target: str) -> list[dict]:
    chains: list[dict] = []
    by_category: dict[str, list[dict]] = {}
    for finding in findings:
        by_category.setdefault(finding.get("category", ""), []).append(finding)

    def add(name: str, severity: str, description: str, related: list[dict], steps: list[str]) -> None:
        if not related:
            return
        hosts = sorted({f.get("host") for f in related if f.get("host")})
        chains.append({
            "id": f"CHAIN-{len(chains) + 1:02d}",
            "name": name,
            "severity": severity,
            "hosts": hosts,
            "description": description,
            "steps": steps,
            "mitre_ids": sorted({f.get("mitre_id") for f in related if f.get("mitre_id")}),
            "finding_ids": [f.get("id") for f in related],
            "findings": [{"id": f.get("id"), "title": f.get("title"), "host": f.get("host"),
                          "severity": f.get("severity")} for f in related],
        })

    admin = [f for f in findings if f.get("category") == "Shadow / Admin Exposure"]
    tls = [f for f in findings if f.get("category") in ("TLS / Encryption", "TLS / Expiry", "Unencrypted Transport")]
    takeover = [f for f in findings if f.get("category") == "Subdomain Takeover"]
    dbs = [f for f in findings if f.get("category") == "Network / Port Exposure"
           and any(port in (f.get("title") or "") for port in ("Redis", "MongoDB", "PostgreSQL", "MySQL", "Elasticsearch", "SQL Server"))]
    cves = [f for f in findings if f.get("cve") or f.get("category") == "CVE / Legacy Service"]
    email = [f for f in findings if f.get("category") == "DNS / Email"]
    webs = [f for f in findings if f.get("category") in ("CMS / Web Platform", "Framework / Runtime")]

    add("Credential Interception via Public Admin Surface", "CRITICAL",
        "A publicly reachable administrative/login surface is paired with weak TLS or plaintext transport, enabling credential capture and session hijack.",
        sorted({id(f): f for f in admin + tls}.values(), key=lambda f: f.get("id")),
        ["Enumerate public admin/login panels", "Intercept or downgrade transport", "Replay stolen sessions against privileged interfaces"])
    add("Subdomain Takeover to Trusted-Domain Phishing", "CRITICAL",
        "A dangling cloud CNAME allows an attacker to claim the abandoned resource and serve content under the trusted domain.",
        takeover,
        ["Find orphaned CNAME", "Register the abandoned cloud resource", "Host phishing or malware on the trusted hostname"])
    add("Exposed Data Store to Mass Exfiltration", "CRITICAL",
        "A network-exposed database/cache service complements a public web surface, giving attackers a direct path from recon to data theft.",
        sorted({id(f): f for f in dbs + webs}.values(), key=lambda f: f.get("id")),
        ["Fingerprint web stack", "Reach database/cache port directly", "Dump or ransom production data"])
    add("Legacy CVE Exploitation Path", "HIGH",
        "Version banners map to known CVEs while the service remains Internet-reachable, enabling commodity exploit attempts.",
        cves,
        ["Fingerprint component version", "Select matching public exploit", "Achieve code execution or privilege escalation"])
    add("Email Spoofing plus Admin Exposure", "HIGH",
        "Missing SPF/DMARC lets attackers spoof the domain while an exposed admin portal increases the credibility of targeted phishing.",
        sorted({id(f): f for f in email + admin}.values(), key=lambda f: f.get("id")),
        ["Spoof the organizational domain", "Send targeted phishing to staff", "Harvest credentials from a familiar admin portal"])
    add("Plaintext Login Portal Interception", "HIGH",
        "A login portal served over plaintext HTTP exposes credentials and session cookies to on-path attackers.",
        [f for f in tls if f.get("category") == "Unencrypted Transport"] + [f for f in admin if "Login" in (f.get("title") or "")],
        ["Join the same network path", "Capture cleartext credentials", "Authenticate as a legitimate user"])
    return chains


def analyze_scan(scan: dict, overrides: Any = None, host_stats: dict | None = None) -> dict:
    scan = copy.deepcopy(scan or {})
    target = str(scan.get("target") or "unknown")
    dns_root = scan.get("dns_root") or {}
    subdomains = scan.get("subdomains") or scan.get("assets") or scan.get("hosts") or []
    host_stats = host_stats or {}
    override_index = _override_index(overrides)
    findings: list[dict] = []
    assets: list[dict] = []
    host_scores: dict[str, int] = {}

    if not dns_root.get("has_dmarc"):
        findings.append(_finding(
            "MEDIUM", "DNS / Email", target, "Missing DMARC Policy",
            f"No _dmarc.{target} TXT record found.",
            "Attackers can spoof organizational emails for spear-phishing.",
            f"Publish a TXT record at _dmarc.{target}: v=DMARC1; p=quarantine; rua=mailto:sec@{target}",
        ))
    if not dns_root.get("has_spf"):
        findings.append(_finding(
            "MEDIUM", "DNS / Email", target, "Missing SPF Record",
            f"No v=spf1 TXT record on {target}.",
            "Unauthorized mail servers can send emails pretending to be your domain.",
            "Add a strict SPF TXT record authorizing only legitimate mail relays.",
        ))

    for raw_asset in subdomains:
        if not isinstance(raw_asset, dict):
            continue
        asset = copy.deepcopy(raw_asset)
        host = str(asset.get("host") or asset.get("hostname") or "unknown-host")
        http = asset.setdefault("http", {}) or {}
        tls = asset.setdefault("tls", {}) or {}
        ips = asset.get("ips") or []
        cnames = asset.get("cnames") or []
        open_ports = asset.get("open_ports") or []
        prefix = host.split(".")[0] if host != target else ""
        is_sensitive = any(key in prefix for key in SENSITIVE_PREFIXES)
        reachable = _asset_reachable(asset)
        stats = host_stats.get(host.lower()) or host_stats.get(f"host:{host.lower()}") or {}
        stability = stats.get("stability") or asset.get("stability") or ("active" if reachable else "inactive")
        if stability not in ("active", "flaky", "inactive"):
            stability = "inactive"
        confidence = stats.get("confidence_pct")
        if confidence is None:
            confidence = asset.get("confidence_pct")
        if confidence is None:
            confidence = 90 if reachable else 20
        asset["stability"] = stability
        asset["confidence_pct"] = int(confidence)
        asset["reachable"] = reachable
        asset["seen_count"] = int(stats.get("seen_count", asset.get("seen_count") or 0))
        asset["scan_count"] = int(stats.get("scan_count", asset.get("scan_count") or 0))
        asset["missed_streak"] = int(stats.get("missed_streak", asset.get("missed_streak") or 0))
        host_override = _lookup_override(override_index, _host_override_keys(host))
        if host_override:
            _apply_override(asset, host_override, kind="host")
        h_findings: list[dict] = []

        for port in open_ports:
            try:
                port_num = int(port.get("port") or 0)
            except (TypeError, ValueError):
                continue
            banner = " ".join(str(x) for x in (port.get("service"), port.get("product"), port.get("version")) if x).strip()
            if port_num in RISKY_PORTS:
                severity, title, vector, fix = RISKY_PORTS[port_num]
                h_findings.append(_finding(
                    severity, "Network / Port Exposure", host, title,
                    f"TCP/{port_num} open on {', '.join(ips) or host} ({banner or 'detected'}).",
                    vector, fix,
                ))
            cve = _detect_cve(banner)
            if cve:
                h_findings.append(_finding(
                    "HIGH", "CVE / Legacy Service", host, f"Known CVE in Service Banner ({cve})",
                    f"TCP/{port_num} banner: {banner}", "Public exploit code can target the advertised component version.",
                    "Upgrade the service and suppress version banners; validate exposure from the Internet.",
                    cve=cve,
                ))

        for cname in cnames:
            cname_low = str(cname).lower().rstrip(".")
            if any(pattern in cname_low for pattern in TAKEOVER_TARGETS) and (not ips or not http.get("reachable")):
                h_findings.append(_finding(
                    "CRITICAL", "Subdomain Takeover", host, "Dangling Cloud CNAME Detected",
                    f"CNAME -> {cname_low} (unreachable / unresolved target).",
                    "Attacker registers the abandoned cloud resource and hosts phishing/XSS under your trusted domain.",
                    f"Immediately remove the orphaned DNS CNAME record for {host} or reclaim {cname_low}.",
                ))

        if tls.get("valid") is False:
            h_findings.append(_finding(
                "CRITICAL" if is_sensitive else "HIGH", "TLS / Encryption", host, "Invalid TLS Certificate",
                f"TLS verification failed: {tls.get('error')}",
                "Enables MitM interception and signals unmanaged shadow infrastructure.",
                f"Replace with a valid CA-signed certificate or restrict {host} behind internal VPN.",
            ))
        elif tls.get("days_remaining") is not None and tls["days_remaining"] <= 30:
            days = int(tls["days_remaining"])
            h_findings.append(_finding(
                "HIGH" if days <= 14 else "MEDIUM", "TLS / Expiry", host,
                f"TLS Certificate Expiring in {days} Days",
                f"Issuer: {tls.get('issuer')} | {days} days left.",
                "Imminent service outage or user habituation to bypassing browser cert warnings.",
                "Automate certificate renewal (ACME / certbot) and enable expiry alerting at 30 days.",
            ))

        url = str(http.get("url") or "")
        if http.get("reachable") and url.startswith("http://"):
            h_findings.append(_finding(
                "CRITICAL" if is_sensitive else "HIGH", "Unencrypted Transport", host,
                "Service Exposed Over Plaintext HTTP",
                f"Reachable at {url} (HTTP {http.get('status')}).",
                "Credentials, session cookies, and API tokens transmitted in cleartext.",
                "Enforce HTTPS with a 301 redirect and enable Strict-Transport-Security (HSTS).",
            ))

        if is_sensitive and http.get("reachable"):
            h_findings.append(_finding(
                "HIGH", "Shadow / Admin Exposure", host,
                f"Publicly Reachable Sensitive Surface ({prefix})",
                f"HTTP {http.get('status')} at {url} on IP {', '.join(ips) or 'N/A'}.",
                "Prime target for credential stuffing, debug-interface abuse, and unpatched exploits.",
                f"Restrict {host} via IP allowlist, Zero-Trust proxy, or internal VPN; disable public routing.",
            ))

        banners = [str(b) for b in (http.get("server"), http.get("x_powered_by")) if b]
        banners += [f"{p.get('product')} {p.get('version')}".strip() for p in open_ports if p.get("product")]
        version_leaks = [b for b in banners if re.search(r"/\d+\.\d+|\d+\.\d+\.\d+", b)]
        if version_leaks:
            joined = " ".join(version_leaks)
            cve = _detect_cve(joined)
            h_findings.append(_finding(
                "HIGH" if cve or any(x in joined.lower() for x in ("werkzeug", "php/7", "2.4.49")) else "MEDIUM",
                "Fingerprinting / Legacy Stack", host, "Detailed Software Version Exposed",
                f"Headers/services leak: {', '.join(version_leaks)}",
                "Accelerates attacker CVE matching and automated exploit targeting.",
                "Upgrade legacy runtimes, suppress Server/X-Powered-By headers, and never run dev servers in prod.",
                cve=cve,
            ))

        missing = list(http.get("missing_headers") or [])
        if http.get("reachable") and missing:
            severity = "HIGH" if len(missing) >= 3 else ("MEDIUM" if len(missing) >= 2 else "LOW")
            h_findings.append(_finding(
                severity, "HTTP Hardening", host, f"Missing {len(missing)} Security Headers",
                f"Missing: {', '.join(missing)}",
                "Increases exposure to clickjacking, MIME sniffing, XSS, and SSL stripping.",
                "Configure HSTS, CSP, X-Frame-Options, and X-Content-Type-Options on the reverse proxy.",
            ))

        h_findings.extend(_signature_findings(asset, host))

        for finding in h_findings:
            override = _lookup_override(override_index, _finding_override_keys(finding))
            if override:
                _apply_override(finding, override, kind="finding")
        findings.extend(h_findings)

        active = [f for f in h_findings if f.get("status") not in SUPPRESSED_STATUSES]
        score = min(100, sum(SEV_WEIGHT.get(f["severity"], 0) for f in active))
        host_scores[host] = score
        asset["host_score"] = score
        asset["severity"] = _score_to_level(score)
        asset["finding_count"] = len(h_findings)
        asset["severity_counts"] = {sev: sum(1 for f in h_findings if f["severity"] == sev)
                                    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        assets.append(asset)

    # Stable unique IDs (fingerprint prefix can theoretically collide).
    used: set[str] = set()
    for finding in findings:
        base = finding["id"]
        candidate, suffix = base, 2
        while candidate in used:
            candidate = f"{base}-{suffix}"
            suffix += 1
        finding["id"] = candidate
        used.add(candidate)
    findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f.get("host") or "", f.get("title") or ""))

    chains = _build_chains(findings, target)
    counts = {sev: sum(1 for f in findings if f.get("severity") == sev)
              for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    active_findings = [f for f in findings if f.get("status") not in SUPPRESSED_STATUSES]
    weighted = sum(SEV_WEIGHT.get(f.get("severity"), 0) for f in active_findings)
    overall = min(100, int(weighted))
    grade = "F" if overall >= 75 else "D" if overall >= 55 else "C" if overall >= 35 else "B" if overall >= 15 else "A"
    stability_counts = {key: sum(1 for a in assets if a.get("stability") == key)
                        for key in ("active", "flaky", "inactive")}

    nodes = [{"data": {"id": f"root:{target}", "label": target, "type": "root",
                       "severity": _score_to_level(overall), "score": overall}}]
    edges: list[dict] = []
    for asset in assets:
        host = asset["host"]
        score = int(asset.get("host_score") or 0)
        if host != target:
            nodes.append({"data": {"id": f"host:{host}", "label": host, "type": "host",
                                   "severity": _score_to_level(score), "score": score,
                                   "ips": ", ".join(asset.get("ips") or []),
                                   "stability": asset.get("stability"),
                                   "confidence_pct": asset.get("confidence_pct"),
                                   "findings": asset.get("finding_count", 0)}})
            edges.append({"data": {"source": f"root:{target}", "target": f"host:{host}", "label": "asset"}})
        for cname in asset.get("cnames") or []:
            cid = f"cname:{str(cname).rstrip('.').lower()}"
            if not any(n["data"]["id"] == cid for n in nodes):
                nodes.append({"data": {"id": cid, "label": str(cname).rstrip("."), "type": "external",
                                       "severity": "CRITICAL" if score >= 30 else "LOW"}})
            edges.append({"data": {"source": f"host:{host}" if host != target else f"root:{target}",
                                   "target": cid, "label": "CNAME"}})
    for finding in findings:
        if finding["severity"] in ("CRITICAL", "HIGH") or finding.get("status") not in SUPPRESSED_STATUSES and finding["severity"] == "MEDIUM" and finding.get("source") == "signature":
            fid = f"find:{finding['id']}"
            source = f"root:{target}" if finding["host"] == target else f"host:{finding['host']}"
            nodes.append({"data": {"id": fid, "label": finding["title"], "type": "finding",
                                   "severity": finding["severity"], "finding_id": finding["id"],
                                   "mitre_id": finding.get("mitre_id"), "cve": finding.get("cve")}})
            edges.append({"data": {"source": source, "target": fid, "label": finding["severity"]}})

    summary = {
        "exposure_score": overall,
        "grade": grade,
        "risk_level": _score_to_level(overall),
        "assets_discovered": len(assets),
        "findings_total": len(findings),
        "active_findings": len(active_findings),
        "suppressed_findings": len(findings) - len(active_findings),
        "chains_detected": len(chains),
        "severity_counts": counts,
        "stability_counts": stability_counts,
        "avg_confidence_pct": round(sum(a.get("confidence_pct", 0) for a in assets) / len(assets), 1) if assets else 0,
        "assets_active": stability_counts.get("active", 0),
        "assets_flaky": stability_counts.get("flaky", 0),
        "assets_inactive": stability_counts.get("inactive", 0),
        "signature_hits": sum(1 for f in findings if f.get("source") == "signature"),
        "analyzed_at": _now(),
    }
    return {
        "summary": summary,
        "host_scores": host_scores,
        "attack_chains": chains,
        "findings": findings,
        "graph": {"nodes": nodes, "edges": edges},
        "assets": assets,
    }


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------
def _scan_index(scan: dict) -> tuple[dict[str, dict], dict[str, dict], int]:
    hosts = scan.get("subdomains") or scan.get("assets") or scan.get("hosts") or []
    index: dict[str, dict] = {}
    for asset in hosts:
        if not isinstance(asset, dict):
            continue
        host = str(asset.get("host") or asset.get("hostname") or "")
        if not host:
            continue
        services: set[str] = set()
        for port in asset.get("open_ports") or []:
            services.add(f"tcp/{port.get('port')}/{port.get('service') or 'unknown'}")
        http = asset.get("http") or {}
        if http.get("reachable"):
            services.add(f"http/{http.get('status')}/{http.get('url')}")
            services.update(f"tech/{tech}" for tech in http.get("technologies") or [])
        tls = asset.get("tls") or {}
        services.add(f"tls/{tls.get('valid')}")
        index[host.lower()] = {
            "host": host, "services": sorted(services), "asset": asset,
            "reachable": bool(http.get("reachable") or asset.get("open_ports") or tls.get("valid") is True),
        }
    findings = {}
    for finding in scan.get("findings") or []:
        key = str(finding.get("fingerprint") or finding.get("id") or "")
        if key:
            findings[key] = finding
    score = int((scan.get("summary") or {}).get("exposure_score") or 0)
    return index, findings, score


def _asset_brief(asset: dict) -> dict:
    http = asset.get("http") or {}
    return {
        "host": asset.get("host"),
        "ips": asset.get("ips") or [],
        "cnames": asset.get("cnames") or [],
        "url": http.get("url"),
        "technologies": http.get("technologies") or [],
        "open_ports": [p.get("port") for p in asset.get("open_ports") or []],
        "stability": asset.get("stability"),
        "confidence_pct": asset.get("confidence_pct"),
        "host_score": asset.get("host_score"),
    }


def _finding_brief(finding: dict) -> dict:
    return {
        "id": finding.get("id"),
        "fingerprint": finding.get("fingerprint"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "host": finding.get("host"),
        "cve": finding.get("cve"),
        "mitre_id": finding.get("mitre_id"),
    }


def compute_drift(previous: dict, current: dict) -> dict:
    prev_index, prev_findings, prev_score = _scan_index(previous or {})
    curr_index, curr_findings, curr_score = _scan_index(current or {})
    new_assets = [_asset_brief(curr_index[key]["asset"]) for key in sorted(curr_index.keys() - prev_index.keys())]
    removed_assets = [_asset_brief(prev_index[key]["asset"]) for key in sorted(prev_index.keys() - curr_index.keys())]
    changed_services: list[dict] = []
    flaky_assets: list[dict] = []
    for key in sorted(prev_index.keys() & curr_index.keys()):
        before, after = prev_index[key], curr_index[key]
        added = sorted(set(after["services"]) - set(before["services"]))
        removed = sorted(set(before["services"]) - set(after["services"]))
        went_offline = before["reachable"] and not after["reachable"]
        if not added and not removed and not went_offline:
            continue
        stability = after["asset"].get("stability")
        item = {
            "host": after["host"],
            "added": added,
            "removed": removed,
            "went_offline": went_offline,
            "stability": stability,
            "confidence_pct": after["asset"].get("confidence_pct"),
            "before_reachable": before["reachable"],
            "after_reachable": after["reachable"],
        }
        changed_services.append(item)
        if went_offline or stability in ("flaky", "inactive"):
            flaky_assets.append(item)
    new_findings = [_finding_brief(curr_findings[k]) for k in sorted(curr_findings.keys() - prev_findings.keys())]
    resolved_findings = [_finding_brief(prev_findings[k]) for k in sorted(prev_findings.keys() - curr_findings.keys())]
    return {
        "score_delta": curr_score - prev_score,
        "previous_score": prev_score,
        "current_score": curr_score,
        "new_assets": new_assets,
        "removed_assets": removed_assets,
        "changed_services": changed_services,
        "flaky_assets": flaky_assets,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "counts": {
            "new_assets": len(new_assets),
            "removed_assets": len(removed_assets),
            "changed_services": len(changed_services),
            "flaky_assets": len(flaky_assets),
            "new_findings": len(new_findings),
            "resolved_findings": len(resolved_findings),
        },
    }


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------
def _host_context(scan: dict) -> dict[str, dict]:
    out = {}
    for asset in scan.get("subdomains") or scan.get("assets") or []:
        if isinstance(asset, dict) and asset.get("host"):
            out[str(asset["host"]).lower()] = asset
    return out


def export_csv(scan_result: dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([
        "scan_id", "finding_id", "severity", "status", "host", "asset_ips", "asset_url",
        "title", "category", "evidence", "attack_vector", "remediation", "mitre_id",
        "mitre_tactic", "cve", "fingerprint", "notes", "tags", "stability",
        "confidence_pct", "technologies", "open_ports",
    ])
    contexts = _host_context(scan_result)
    scan_id = scan_result.get("scan_id") or scan_result.get("id") or ""
    for finding in scan_result.get("findings") or []:
        host = str(finding.get("host") or "")
        asset = contexts.get(host.lower(), {})
        http = asset.get("http") or {}
        tags = finding.get("tags") or []
        writer.writerow([
            scan_id,
            finding.get("id", ""),
            finding.get("severity", ""),
            finding.get("status") or "open",
            host,
            ", ".join(asset.get("ips") or []),
            http.get("url") or "",
            finding.get("title", ""),
            finding.get("category", ""),
            finding.get("evidence", ""),
            finding.get("attack_vector", ""),
            finding.get("remediation", ""),
            finding.get("mitre_id", ""),
            finding.get("mitre_tactic", ""),
            finding.get("cve") or "",
            finding.get("fingerprint", ""),
            (finding.get("notes") or "").replace("\r", " ").replace("\n", " "),
            "; ".join(str(t) for t in tags),
            asset.get("stability", ""),
            asset.get("confidence_pct", ""),
            ", ".join(http.get("technologies") or []),
            ", ".join(f"{p.get('port')}/{p.get('service')}" for p in asset.get("open_ports") or []),
        ])
    return buffer.getvalue()


def export_defectdojo_json(scan_result: dict) -> dict:
    contexts = _host_context(scan_result)
    scan_date = str(scan_result.get("scanned_at") or _now())[:10]
    findings = []
    for finding in scan_result.get("findings") or []:
        host = str(finding.get("host") or "")
        asset = contexts.get(host.lower(), {})
        http = asset.get("http") or {}
        status = str(finding.get("status") or "open").lower()
        severity = str(finding.get("severity") or "LOW").capitalize()
        if severity not in ("Critical", "High", "Medium", "Low", "Info"):
            severity = "Low"
        tags = [str(t) for t in (finding.get("tags") or [])]
        if "asi-mini" not in tags:
            tags.append("asi-mini")
        references = ["ASI Mini — Attack Surface Intelligence"]
        if finding.get("mitre_id"):
            references.append(f"MITRE ATT&CK {finding['mitre_id']} ({finding.get('mitre_tactic') or ''})".strip())
        if finding.get("cve"):
            references.append(str(finding["cve"]))
        if finding.get("fingerprint"):
            references.append(f"fingerprint:{finding['fingerprint']}")
        endpoint = http.get("url") or (f"https://{host}" if host and "." in host else host)
        findings.append({
            "title": finding.get("title") or "ASI finding",
            "description": "\n".join(filter(None, [
                finding.get("evidence") or "",
                f"Category: {finding.get('category') or 'n/a'}",
                f"MITRE: {finding.get('mitre_id') or 'n/a'} / {finding.get('mitre_tactic') or 'n/a'}",
                f"CVE: {finding.get('cve')}" if finding.get("cve") else "",
                f"Analyst notes: {finding.get('notes')}" if finding.get("notes") else "",
                f"Stability: {asset.get('stability') or 'n/a'} ({asset.get('confidence_pct', 'n/a')}% confidence)",
            ])),
            "severity": severity,
            "mitigation": finding.get("remediation") or "Review the asset and apply vendor hardening guidance.",
            "impact": finding.get("attack_vector") or "Increases the organization's attack surface.",
            "references": "\n".join(references),
            "active": status not in SUPPRESSED_STATUSES,
            "verified": False,
            "false_p": status == "false_positive",
            "duplicate": False,
            "date": scan_date,
            "cweid": 0,
            "cvssv3_score": {"Critical": 9.8, "High": 8.1, "Medium": 5.3, "Low": 2.6, "Info": 0.0}.get(severity, 0.0),
            "unique_id_from_tool": finding.get("fingerprint") or finding.get("id") or "",
            "vuln_id_from_tool": finding.get("id") or "",
            "component_name": host,
            "component_version": "",
            "service": finding.get("category") or "Attack Surface",
            "endpoint": endpoint,
            "tags": tags,
        })
    return {"findings": findings}
