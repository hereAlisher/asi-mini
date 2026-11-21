"""ASI Mini scanner.

Target planning/slicing for >10k IP ranges without expanding CIDRs into memory,
rate-limited + time-windowed live discovery, safe read-only HTTP/TLS/DNS
fingerprinting, signature matching, Nmap/CSV/JSON importers and demo datasets.
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:  # optional at runtime, but installed in .venv
    import httpx
except Exception:  # pragma: no cover
    httpx = None

try:
    import dns.resolver  # type: ignore
except Exception:  # pragma: no cover
    dns = None

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
]
FALLBACK_PREFIXES = ["www", "mail", "dev", "staging", "admin", "api", "vpn", "test"]
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 445: "microsoft-ds", 1433: "mssql", 2375: "docker",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch", 11211: "memcached",
    15672: "rabbitmq-management", 27017: "mongodb",
}

DEFAULT_SIGNATURES: list[dict] = [
    {
        "name": "WordPress CMS Detected", "category": "CMS / Web Platform", "match_type": "html",
        "match_value": r"wp-content|wp-includes|wordpress", "severity": "MEDIUM",
        "description": "WordPress content management system is publicly reachable and its asset paths are enumerable.",
        "remediation": "Keep WordPress core, themes and plugins patched; disable XML-RPC and directory listing; front with a WAF.",
        "mitre_id": "T1190",
    },
    {
        "name": "Drupal CMS Detected", "category": "CMS / Web Platform", "match_type": "html",
        "match_value": r"drupal|sites/default/files", "severity": "MEDIUM",
        "description": "Drupal CMS is exposed; contributed modules frequently carry remote code execution flaws.",
        "remediation": "Patch Drupal core/modules, remove unused modules and enforce HTTPS plus a restrictive CSP.",
        "mitre_id": "T1190",
    },
    {
        "name": "PHP Runtime Version Disclosed", "category": "Framework / Runtime", "match_type": "header",
        "match_key": "x-powered-by", "match_value": r"php", "severity": "MEDIUM",
        "description": "The X-Powered-By header reveals the PHP runtime, accelerating CVE matching.",
        "remediation": "Set expose_php=Off and strip X-Powered-By at the reverse proxy.",
        "mitre_id": "T1592",
    },
    {
        "name": "ASP.NET Session Cookie Exposed", "category": "Framework / Runtime", "match_type": "cookie",
        "match_value": r"asp\.net_sessionid|aspnet_sessionid", "severity": "LOW",
        "description": "ASP.NET session cookie reveals the application stack and session handling model.",
        "remediation": "Disable cookie-less sessions, set HttpOnly/Secure/SameSite and suppress stack-identifying cookies.",
        "mitre_id": "T1592",
    },
    {
        "name": "Java Application Server Session", "category": "Application Server", "match_type": "cookie",
        "match_value": r"jsessionid", "severity": "LOW",
        "description": "JSESSIONID exposes a Java servlet container, commonly Tomcat/Jetty with management surfaces.",
        "remediation": "Harden the servlet container, remove default manager apps and rotate session IDs on login.",
        "mitre_id": "T1592",
    },
    {
        "name": "Exposed Administrative Interface", "category": "Shadow / Admin Exposure", "match_type": "path",
        "path": "/admin", "match_value": "status_lt_400", "severity": "HIGH",
        "description": "An administrative interface answers unauthenticated GET requests from the public Internet.",
        "remediation": "Restrict /admin behind VPN/Zero-Trust, enforce MFA and IP allowlists.",
        "mitre_id": "T1078",
    },
    {
        "name": "Public Login Portal", "category": "Shadow / Admin Exposure", "match_type": "path",
        "path": "/login", "match_value": "status_lt_400", "severity": "LOW",
        "description": "A login portal is publicly reachable and can be targeted with credential stuffing.",
        "remediation": "Enable MFA, rate limiting, lockout and bot detection on the login endpoint.",
        "mitre_id": "T1110",
    },
    {
        "name": "Version Endpoint Disclosure", "category": "Fingerprinting / Legacy Stack", "match_type": "path",
        "path": "/version", "match_value": "status_lt_400", "severity": "LOW",
        "description": "A /version endpoint discloses build information useful for exploit selection.",
        "remediation": "Remove or authenticate version endpoints and suppress build metadata.",
        "mitre_id": "T1592",
    },
    {
        "name": "Staging Surface Publicly Resolvable", "category": "Shadow / Admin Exposure", "match_type": "hostname",
        "match_value": r"^(staging|stage|stg|dev|test|qa)\.", "severity": "HIGH",
        "description": "A staging/development hostname is present in public DNS and may expose pre-production data.",
        "remediation": "Remove public DNS for non-production hosts or protect them with SSO/IP allowlists.",
        "mitre_id": "T1595",
    },
    {
        "name": "IoT / Network Appliance Fingerprint", "category": "IoT / Network Appliance", "match_type": "header",
        "match_key": "server",
        "match_value": r"cisco|asa|hikvision|dahua|mikrotik|routeros|axis|ubiquiti|tp-link|tplink|ipcam|webcam|printer",
        "severity": "HIGH",
        "description": "An Internet-facing IoT or network appliance was fingerprinted; these devices often ship with weak firmware.",
        "remediation": "Patch firmware, disable remote management, change default credentials and segment the device.",
        "mitre_id": "T1190",
    },
]

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.20.0.10" addrtype="ipv4"/>
    <hostnames><hostname name="db-core.internal"/></hostnames>
    <ports>
      <port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql" product="PostgreSQL DB" version="14.2"/></port>
      <port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis key-value store" version="6.2.6"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.20.0.15" addrtype="ipv4"/>
    <hostnames><hostname name="legacy-lab-pc.internal"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows SMB"/></port>
      <port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server" product="Microsoft Terminal Services"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.20.0.21" addrtype="ipv4"/>
    <hostnames><hostname name="edge-switch.internal"/></hostnames>
    <ports>
      <port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="Cisco IOS telnetd"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.9"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.20.0.30" addrtype="ipv4"/>
    <hostnames><hostname name="jenkins-ci.internal"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Jetty" version="9.4.43"/></port>
      <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="3.0.3"/></port>
    </ports>
  </host>
</nmaprun>"""


# ---------------------------------------------------------------------------
# Target parsing / planning / slicing
# ---------------------------------------------------------------------------
def clean_domain(raw: str) -> str:
    d = str(raw or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split(":")[0].strip().strip(".")
    return d


def _split_raw(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        out: list[str] = []
        for item in raw:
            out.extend(_split_raw(item))
        return out
    return [p for p in re.split(r"[\s,;]+", str(raw)) if p.strip()]


def _entry_for(item: str) -> dict | None:
    item = item.strip()
    if not item:
        return None
    # Handle http(s)://host:port/ — strip scheme and path, keep host:port
    url_match = re.match(r"^https?://([^/]+)", item)
    if url_match:
        item = url_match.group(1)
    if "/" in item:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if net.version == 4:
                count = net.num_addresses if net.prefixlen >= 31 else max(net.num_addresses - 2, 1)
                start = int(net.network_address) + (1 if net.prefixlen < 31 else 0)
            else:
                count = net.num_addresses if net.num_addresses <= 65536 else 65536
                start = int(net.network_address)
            return {"kind": "cidr", "raw": item, "value": str(net), "version": net.version,
                    "start": start, "count": int(count)}
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$", item)
    if m:
        try:
            a = int(ipaddress.ip_address(m.group(1)))
            b = int(ipaddress.ip_address(m.group(2)))
        except ValueError:
            a = b = None
        if a is not None and b is not None and b >= a:
            return {"kind": "range", "raw": item, "value": item, "start": a, "count": b - a + 1}
    # Handle host:port (IPv4 or domain) — not IPv6
    port_match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$", item)
    if port_match:
        return {"kind": "hostport", "raw": item, "value": item, "start": 0, "count": 1}
    domain_port_match = re.match(r"^([a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?):(\d+)$", item)
    if domain_port_match and not item.startswith("["):
        return {"kind": "hostport", "raw": item, "value": item, "start": 0, "count": 1}
    try:
        ip = ipaddress.ip_address(item)
        return {"kind": "ip", "raw": item, "value": str(ip), "start": int(ip), "count": 1}
    except ValueError:
        pass
    domain = clean_domain(item)
    if domain and "." in domain:
        return {"kind": "domain", "raw": item, "value": domain, "start": 0, "count": 1}
    return None


def parse_targets(raw_targets: Any) -> tuple[list[dict], int]:
    entries: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in _split_raw(raw_targets):
        entry = _entry_for(item)
        if not entry:
            continue
        key = (entry["kind"], entry["value"])
        if key in seen:
            continue
        seen.add(key)
        entries.append(entry)
    return entries, sum(int(e["count"]) for e in entries)


def plan_targets(raw_targets: Any, rate_limit_rps: float = 5.0, window_minutes: float = 60.0,
                 measured_host_sec: float | None = None) -> dict:
    entries, total = parse_targets(raw_targets)
    rps = max(float(rate_limit_rps or 5.0), 0.1)
    window_sec = max(float(window_minutes or 60.0), 1.0) * 60.0
    # Use measured speed to adapt chunk size if provided
    if measured_host_sec and measured_host_sec > 0:
        hosts_per_window = int(window_sec / measured_host_sec)
        optimal_chunk = min(hosts_per_window, 5000, max(total, 1))
        estimated = round(total * measured_host_sec, 2)
    else:
        estimated = round(total / rps, 2) if total else 0.0
        window_capacity = max(1, int(rps * window_sec))
        optimal_chunk = min(window_capacity, 5000, max(total, 1))
    if total <= 0:
        optimal_chunk = 0
    total_chunks = math.ceil(total / optimal_chunk) if optimal_chunk else 0
    windows_needed = math.ceil(estimated / window_sec) if total else 0
    sample = slice_targets(raw_targets, 0, min(total, 5))["targets"] if total else []
    kinds: dict[str, int] = {}
    for e in entries:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    return {
        "total_hosts": int(total),
        "optimal_chunk_size": int(optimal_chunk),
        "total_chunks": int(total_chunks),
        "estimated_duration_sec": estimated,
        "windows_needed": int(max(windows_needed, 0)),
        "supports_10k_scale": bool(total >= 10000),
        "rate_limit_rps": rps,
        "window_minutes": round(window_sec / 60.0, 2),
        "window_capacity": int(window_sec / rps) if not (measured_host_sec and measured_host_sec > 0) else int(window_sec / measured_host_sec),
        "target_entries": len(entries),
        "target_types": kinds,
        "memory_safe": True,
        "expansion_strategy": "lazy_cidr_arithmetic",
        "sample_targets": sample,
        "eta_human": _human_duration(estimated),
        "adaptive": bool(measured_host_sec and measured_host_sec > 0),
    }


def _human_duration(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def slice_targets(raw_targets: Any, cursor: int = 0, limit: int = 256) -> dict:
    entries, total = parse_targets(raw_targets)
    cursor = max(0, int(cursor or 0))
    limit = max(1, int(limit or 256))
    out: list[str] = []
    position = 0
    for entry in entries:
        if len(out) >= limit:
            break
        count = int(entry["count"])
        if cursor >= position + count:
            position += count
            continue
        offset = max(0, cursor - position)
        take = min(count - offset, limit - len(out))
        if entry["kind"] in ("cidr", "range"):
            for idx in range(offset, offset + take):
                out.append(str(ipaddress.ip_address(int(entry["start"]) + idx)))
        else:
            out.append(entry["value"])
        position += count
    next_cursor = cursor + len(out)
    if next_cursor >= total:
        next_cursor = None
    return {
        "targets": out,
        "cursor": cursor,
        "next_cursor": next_cursor,
        "total_hosts": int(total),
        "returned": len(out),
        "has_more": next_cursor is not None,
    }


# ---------------------------------------------------------------------------
# DNS / TLS / HTTP fingerprinting
# ---------------------------------------------------------------------------
def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_records(name: str, rtype: str) -> list[str]:
    if dns is not None:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 3.0
            answers = resolver.resolve(name, rtype)
            out = []
            for r in answers:
                if rtype == "MX":
                    out.append(str(getattr(r, "exchange", r)).strip("."))
                else:
                    out.append(str(r).strip('"').strip("."))
            return out
        except Exception:
            pass
    if rtype == "A":
        try:
            return sorted({info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET)})
        except OSError:
            return []
    return []


def resolve_root_dns(domain: str) -> dict:
    txt = _resolve_records(domain, "TXT")
    dmarc = _resolve_records(f"_dmarc.{domain}", "TXT")
    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    return {
        "mx": _resolve_records(domain, "MX"),
        "txt": txt[:8],
        "ns": _resolve_records(domain, "NS")[:5],
        "spf": spf,
        "dmarc": dmarc[0] if dmarc else None,
        "has_spf": bool(spf),
        "has_dmarc": any("v=dmarc1" in t.lower() for t in dmarc),
    }


def _default_tls() -> dict:
    return {"valid": None, "days_remaining": None, "issuer": None, "subject": None,
            "expires_at": None, "error": "no_tls"}


def _default_http() -> dict:
    return {
        "reachable": False, "url": None, "scheme": None, "status": None, "title": None,
        "server": None, "x_powered_by": None, "headers": {}, "cookies": [], "redirects": [],
        "favicon_hash": None, "technologies": [], "missing_headers": [], "paths": {},
        "body_snippet": "", "matched_signatures": [], "footer_version": None,
    }


def _cert_info(cert: dict, valid: bool, error: str | None) -> dict:
    try:
        exp_ts = ssl.cert_time_to_seconds(cert["notAfter"])
        days_left = int((exp_ts - time.time()) / 86400)
        expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()
    except Exception:
        days_left = None
        expires_at = None
    issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "Unknown")
    subject = dict(x[0] for x in cert.get("subject", ())).get("commonName")
    return {"valid": valid, "days_remaining": days_left, "issuer": issuer,
            "subject": subject, "expires_at": expires_at, "error": error}


def inspect_tls(host: str, port: int = 443, timeout: float = 3.0) -> dict:
    if _is_ip(host):
        # No hostname to verify; still collect certificate expiry/issuer safely.
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ssl._create_unverified_context().wrap_socket(sock, server_hostname=None) as ssock:
                    return _cert_info(ssock.getpeercert(), None, "ip_target_no_hostname_check")
        except Exception:
            return _default_tls()
    server_name = host
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                return _cert_info(ssock.getpeercert(), True, None)
    except ssl.SSLCertVerificationError as exc:
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                    info = _cert_info(ssock.getpeercert(), False, getattr(exc, "reason", str(exc)))
                    return info
        except Exception:
            return {"valid": False, "days_remaining": None, "issuer": None, "subject": None,
                    "expires_at": None, "error": getattr(exc, "reason", str(exc))}
    except Exception:
        return _default_tls()


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_FOOTER_RE = re.compile(r"<footer[^>]*>(.*?)</footer>", re.I | re.S)
_VERSION_RE = re.compile(
    r"(?:powered by|version|ver\.?|v\.?)\s*([\w.\-]*?[\d]+[\w.\-]*)", re.I
)


def _extract_title(html: str) -> str | None:
    match = _TITLE_RE.search(html or "")
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:200] or None


def _extract_footer_version(html: str) -> str | None:
    """Safely extract a version string from <footer> content."""
    m = _FOOTER_RE.search(html or "")
    if not m:
        return None
    footer_text = re.sub(r"\s+", " ", m.group(1)).strip()
    vm = _VERSION_RE.search(footer_text)
    if vm:
        return vm.group(1).strip()[:80]
    # Fallback: look for any version-like token in footer
    tok = re.search(r"\bv?\d+\.\d+(?:\.\d+)?\b", footer_text)
    return tok.group(0)[:80] if tok else None


def _regex_match(pattern: str | None, text: str) -> bool:
    if not pattern:
        return False
    try:
        return re.search(pattern, text or "", re.I) is not None
    except re.error:
        return (pattern or "").lower() in (text or "").lower()


def _path_match(condition: Any, status: int | None) -> bool:
    if status is None:
        return False
    if condition is None:
        return status < 400
    cond = str(condition).strip().lower()
    if cond.isdigit():
        return status == int(cond)
    if cond.startswith("status_in:"):
        values = {v.strip() for v in cond.split(":", 1)[1].split(",")}
        return str(status) in values
    if cond == "exists":
        return status != 404
    if cond == "status_lt_400":
        return status < 400
    return status < 400


async def _fetch_favicon(client: Any, base: str) -> str | None:
    try:
        r = await client.get(f"{base}/favicon.ico", timeout=4.0)
        if r.status_code == 200 and r.content:
            return hashlib.sha256(r.content).hexdigest()[:16]
    except Exception:
        pass
    return None


async def _fetch_paths(client: Any, base: str, paths: Iterable[str]) -> dict:
    out: dict[str, dict] = {}
    for path in sorted(set(p for p in paths if p and p.startswith("/"))):
        try:
            r = await client.get(f"{base}{path}", timeout=4.0)
            out[path] = {"status": r.status_code, "location": r.headers.get("location"),
                         "length": len(r.content or b"")}
        except Exception:
            out[path] = {"status": None, "location": None, "length": 0}
    return out


async def fingerprint_http(host: str, client: Any, signature_paths: Iterable[str] | None = None,
                           port: int | None = None) -> dict:
    result = _default_http()
    if client is None:
        return result
    # Build target host:port string for non-standard ports
    if port is not None and port not in (80, 443):
        target = f"{host}:{port}"
        schemes = ("http", "https")  # try HTTP first for non-standard ports
    else:
        target = host
        schemes = ("https", "http")
    for scheme in schemes:
        try:
            r = await client.get(f"{scheme}://{target}/", timeout=6.0)
        except Exception:
            continue
        text = r.text[:200000] if r.text else ""
        headers = {k.lower(): v[:300] for k, v in r.headers.items() if k.lower() != "set-cookie"}
        cookies = []
        for raw_cookie in r.headers.get_list("set-cookie"):
            name = raw_cookie.split("=", 1)[0].strip()
            if name and name not in cookies:
                cookies.append(name)
        base = f"{scheme}://{target}"
        result.update({
            "reachable": True,
            "url": str(r.url),
            "scheme": scheme,
            "status": r.status_code,
            "title": _extract_title(text),
            "footer_version": _extract_footer_version(text),
            "server": headers.get("server"),
            "x_powered_by": headers.get("x-powered-by"),
            "headers": headers,
            "cookies": cookies,
            "redirects": [{"status": h.status_code, "url": str(h.url)} for h in r.history],
            "favicon_hash": await _fetch_favicon(client, base),
            "missing_headers": [h for h in SEC_HEADERS if h not in headers],
            "paths": await _fetch_paths(client, base, signature_paths or []),
            "body_snippet": text[:5000],
        })
        return result
    return result


def detect_technologies(http: dict, open_ports: list[dict] | None = None) -> list[str]:
    tech: set[str] = set()
    server = (http.get("server") or "").lower()
    powered = (http.get("x_powered_by") or "").lower()
    body = (http.get("body_snippet") or "").lower()
    footer = (http.get("footer_version") or "").lower()
    headers = http.get("headers") or {}
    cookies = [str(c).lower() for c in (http.get("cookies") or [])]
    if "wp-content" in body or "wp-includes" in body or "wordpress" in body or "wordpress" in footer:
        tech.add("WordPress")
    if "drupal" in body or "drupal" in footer:
        tech.add("Drupal")
    if "joomla" in body:
        tech.add("Joomla")
    if "php" in powered or "phpsessid" in cookies:
        tech.add("PHP")
    if "asp.net" in powered or "x-aspnet-version" in headers or any("asp.net_sessionid" in c for c in cookies):
        tech.add("ASP.NET")
    if "jsessionid" in cookies or "tomcat" in server or "jetty" in server:
        tech.add("Java")
    if "werkzeug" in server or "flask" in powered:
        tech.add("Flask")
    if "express" in powered:
        tech.add("Express")
    if "django" in body or "csrftoken" in cookies:
        tech.add("Django")
    for name, label in (("nginx", "nginx"), ("apache", "Apache"), ("iis", "IIS"), ("caddy", "Caddy"),
                        ("lighttpd", "Lighttpd"), ("openresty", "OpenResty")):
        if name in server:
            tech.add(label)
    iot_markers = ("cisco", "asa", "hikvision", "dahua", "mikrotik", "routeros", "axis",
                   "ubiquiti", "tp-link", "tplink", "ipcam", "webcam", "printer", "camera")
    if any(marker in server or marker in body or marker in footer for marker in iot_markers):
        tech.add("IoT")
    if "cisco" in server:
        tech.add("Cisco ASA")
    for port in open_ports or []:
        svc = (port.get("service") or "").lower()
        product = (port.get("product") or "").lower()
        if svc == "redis" or "redis" in product:
            tech.add("Redis")
        elif svc in ("mysql", "postgresql", "mongodb", "mssql", "elasticsearch"):
            tech.add(svc.title())
    return sorted(tech)


def evaluate_signatures(asset: dict, signatures: list[dict] | None = None) -> list[dict]:
    signatures = signatures if signatures is not None else DEFAULT_SIGNATURES
    http = asset.get("http") or {}
    host = asset.get("host") or ""
    hits: list[dict] = []
    seen: set[str] = set()
    for sig in signatures:
        if not sig.get("enabled", True):
            continue
        name = sig.get("name") or "Signature Match"
        if name in seen:
            continue
        match_type = str(sig.get("match_type") or "html").lower()
        matched = False
        evidence = ""
        if match_type == "header":
            key = str(sig.get("match_key") or "").lower()
            value = (http.get("headers") or {}).get(key, "")
            if value and _regex_match(sig.get("match_value"), value):
                matched, evidence = True, f"Header {key}: {value}"
        elif match_type == "cookie":
            names = "; ".join(http.get("cookies") or [])
            if names and _regex_match(sig.get("match_value") or sig.get("match_key"), names):
                matched, evidence = True, f"Cookies: {names}"
        elif match_type == "html":
            haystack = " ".join([http.get("body_snippet") or "", http.get("title") or "",
                                 http.get("footer_version") or "",
                                 " ".join(http.get("technologies") or [])])
            if _regex_match(sig.get("match_value"), haystack):
                matched, evidence = True, f"HTML pattern '{sig.get('match_value')}' matched on {host}"
        elif match_type == "favicon_hash":
            value = http.get("favicon_hash")
            if value and _regex_match(sig.get("match_value"), value):
                matched, evidence = True, f"Favicon SHA-256 prefix {value}"
        elif match_type == "hostname":
            if _regex_match(sig.get("match_value"), host):
                matched, evidence = True, f"Hostname {host}"
        elif match_type == "title":
            if _regex_match(sig.get("match_value"), http.get("title") or ""):
                matched, evidence = True, f"Title '{http.get('title')}'"
        elif match_type == "path":
            path = sig.get("path") or sig.get("match_key") or "/"
            res = (http.get("paths") or {}).get(path) or {}
            status = res.get("status")
            if _path_match(sig.get("match_value"), status):
                matched, evidence = True, f"Read-only GET {path} -> HTTP {status}"
        if matched:
            seen.add(name)
            hits.append({
                "signature_id": sig.get("id"), "name": name,
                "category": sig.get("category") or "Signature Match",
                "severity": str(sig.get("severity") or "MEDIUM").upper(),
                "description": sig.get("description") or "",
                "remediation": sig.get("remediation") or "",
                "mitre_id": sig.get("mitre_id"), "cve": sig.get("cve"),
                "match_type": match_type, "path": sig.get("path"), "evidence": evidence,
            })
    return hits


async def _tcp_probe(host: str, port: int, timeout: float = 1.2) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def tcp_port_check(host: str, ports: list[int], timeout: float = 1.2) -> list[dict]:
    async def probe(port: int):
        return port, await _tcp_probe(host, port, timeout)
    results = await asyncio.gather(*(probe(p) for p in ports), return_exceptions=True)
    open_ports = []
    for item in results:
        if isinstance(item, Exception):
            continue
        port, is_open = item
        if is_open:
            open_ports.append({"port": int(port), "protocol": "tcp",
                               "service": SERVICE_NAMES.get(int(port), "unknown"),
                               "product": "", "version": ""})
    return open_ports


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap_scan(hosts: list[str], ports: list[int], timeout: float = 60.0) -> dict[str, list[dict]] | None:
    """Optional Nmap subprocess. Returns None so callers fall back to async TCP."""
    if not hosts or not nmap_available():
        return None
    try:
        cmd = ["nmap", "-Pn", "-sT", "-sV", "-p", ",".join(str(p) for p in ports), "-oX", "-", *hosts[:64]]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0 or "<nmaprun" not in proc.stdout:
            return None
        parsed = parse_nmap_xml(proc.stdout, "nmap-subprocess.xml")
        return {str(h["host"]).lower(): h.get("open_ports", []) for h in parsed["subdomains"]}
    except Exception:
        return None


class _RateLimiter:
    def __init__(self, rps: float):
        self.interval = 1.0 / max(float(rps or 1.0), 0.1)
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if self._next > now:
                await asyncio.sleep(self._next - now)
                now = time.monotonic()
            self._next = max(now, self._next) + self.interval


def _parse_dt(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    try:
        text = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _is_reachable(asset: dict) -> bool:
    http = asset.get("http") or {}
    tls = asset.get("tls") or {}
    status = http.get("status")
    if status is not None:
        try:
            if int(status) >= 500:
                return False
        except (TypeError, ValueError):
            pass
    return bool(http.get("reachable") or asset.get("open_ports") or tls.get("valid") is True)


async def _scan_one(host: str, sem: asyncio.Semaphore, client: Any, *, scan_ports: bool,
                    ports: list[int], signatures: list[dict], nmap_ports: list[dict] | None,
                    is_flaky: bool = False) -> list[dict]:
    async with sem:
        # Handle host:port targets (e.g. "127.0.0.1:9001" or "example.com:8080")
        port_override: int | None = None
        if ":" in host and not host.startswith("["):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                parts = host.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    host = parts[0]
                    port_override = int(parts[1])

        a_records, cnames = await asyncio.gather(
            asyncio.to_thread(_resolve_records, host, "A"),
            asyncio.to_thread(_resolve_records, host, "CNAME"),
        )
        signature_paths = [s.get("path") for s in signatures
                           if str(s.get("match_type", "")).lower() == "path" and s.get("path")]
        tls = await asyncio.to_thread(inspect_tls, host)

        # Determine which ports to TCP-check
        if port_override is not None:
            check_ports = [port_override]
        else:
            check_ports = ports

        if nmap_ports is not None:
            open_ports = list(nmap_ports)
        elif scan_ports or port_override is not None:
            target = a_records[0] if a_records else host
            open_ports = await tcp_port_check(target, check_ports)
        else:
            open_ports = []

        # --- Multi-port HTTP fingerprinting ---
        # Try default HTTP fingerprinting first (ports 80/443)
        http = await fingerprint_http(host, client, signature_paths)

        # For each discovered open non-standard port, fingerprint HTTP
        port_fingerprints: dict[int, dict] = {}
        non_standard_open = [p for p in open_ports
                             if (p.get("port") if isinstance(p, dict) else p) not in (80, 443)]
        for p in non_standard_open:
            port_num = p.get("port") if isinstance(p, dict) else p
            if port_num in port_fingerprints:
                continue
            pf = await fingerprint_http(host, client, signature_paths, port=port_num)
            if pf.get("reachable"):
                port_fingerprints[port_num] = pf

        # If default HTTP didn't connect but a non-standard port did, use the first as primary
        if not http.get("reachable") and port_fingerprints:
            http = next(iter(port_fingerprints.values()))

        http["technologies"] = detect_technologies(http, open_ports)

        # Build the base host asset
        base_asset = {
            "host": host,
            "ips": a_records,
            "cnames": cnames,
            "mx": [],
            "tls": tls,
            "http": http,
            "open_ports": open_ports,
            "sources": ["live_dns"] + (["nmap"] if nmap_ports is not None else (["tcp"] if scan_ports else [])),
        }
        base_asset["http"]["matched_signatures"] = evaluate_signatures(base_asset, signatures)

        assets: list[dict] = [base_asset]

        # Create per-port assets for each HTTP-responding non-standard port
        for port_num, pf in port_fingerprints.items():
            port_open = next((p for p in open_ports
                              if (p.get("port") if isinstance(p, dict) else p) == port_num), None)
            if port_open is None:
                port_open = {"port": port_num, "protocol": "tcp",
                             "service": SERVICE_NAMES.get(port_num, "unknown"),
                             "product": "", "version": ""}
            pf_copy = dict(pf)
            pf_copy["technologies"] = detect_technologies(pf_copy, [port_open])
            port_asset = {
                "host": f"{host}:{port_num}",
                "ips": a_records,
                "cnames": cnames,
                "mx": [],
                "tls": _default_tls(),
                "http": pf_copy,
                "open_ports": [port_open],
                "sources": ["live_dns", "tcp"],
            }
            port_asset["http"]["matched_signatures"] = evaluate_signatures(port_asset, signatures)
            assets.append(port_asset)

        # Flaky-host auto-retry on the base asset
        if is_flaky and not _is_reachable(base_asset) and not base_asset.get("retried"):
            await asyncio.sleep(0.3)
            tls2 = await asyncio.to_thread(inspect_tls, host)
            http2 = await fingerprint_http(host, client, signature_paths)
            if not http2.get("reachable") and port_fingerprints:
                http2 = next(iter(port_fingerprints.values()))
            http2["technologies"] = detect_technologies(http2, open_ports)
            http2["matched_signatures"] = evaluate_signatures({
                "host": host, "http": http2, "open_ports": open_ports,
            }, signatures)
            assets[0] = {
                "host": host,
                "ips": a_records,
                "cnames": cnames,
                "mx": [],
                "tls": tls2,
                "http": http2,
                "open_ports": open_ports,
                "sources": ["live_dns"] + (["nmap"] if nmap_ports is not None else (["tcp"] if scan_ports else [])),
                "retried": True,
            }

        return assets


async def scan_targets(
    raw_targets: Any = None,
    *,
    domain: str | None = None,
    rate_limit_rps: float = 5.0,
    window_start: Any = None,
    window_end: Any = None,
    cursor: int = 0,
    batch_limit: int | None = None,
    scan_ports: bool = False,
    allowed_ports: list[int] | None = None,
    signatures: list[dict] | None = None,
    max_concurrency: int = 8,
    dns_root: dict | None = None,
    host_stats: dict | None = None,
) -> dict:
    started = time.perf_counter()
    signatures = signatures if signatures is not None else DEFAULT_SIGNATURES
    ports = sorted({int(p) for p in (allowed_ports or DEFAULT_PORTS) if str(p).isdigit() and 0 < int(p) < 65536})
    entries, total = parse_targets(raw_targets)
    start_cursor = max(0, int(cursor or 0))
    limit = int(batch_limit) if batch_limit else min(max(total, 1), 512)
    target_name = clean_domain(domain) if domain else (entries[0]["value"] if entries else "asi-target")

    def base_result(status: str, next_cursor: int | None, scanned: int = 0) -> dict:
        return {
            "target": target_name, "mode": "live", "scanned_at": datetime.now(timezone.utc).isoformat(),
            "duration_sec": round(time.perf_counter() - started, 3), "scan_status": status,
            "cursor": start_cursor, "next_cursor": next_cursor, "total_hosts": total,
            "hosts_scanned": scanned, "rate_limit_rps": rate_limit_rps,
            "window_start": str(window_start) if window_start else None,
            "window_end": str(window_end) if window_end else None,
            "allowed_ports": ports if scan_ports else [],
            "dns_root": dns_root or (resolve_root_dns(target_name) if domain and "." in target_name else
                                     {"mx": [], "txt": [], "has_spf": True, "has_dmarc": True}),
            "subdomains": [],
        }

    now = datetime.now(timezone.utc)
    window_start_dt, window_end_dt = _parse_dt(window_start), _parse_dt(window_end)
    if window_start_dt and now < window_start_dt:
        return base_result("paused_window_not_started", start_cursor)
    if window_end_dt and now >= window_end_dt:
        return base_result("paused_window_expired", start_cursor)

    slice_info = slice_targets(raw_targets, start_cursor, limit)
    hosts = slice_info["targets"]
    if not hosts:
        return base_result("completed", None)

    # Determine which hosts are currently flaky (from host_history) for auto-retry.
    flaky_hosts: set[str] = set()
    if host_stats:
        for key, stats in host_stats.items():
            if stats.get("stability") == "flaky":
                flaky_hosts.add(str(stats.get("host", key)).lower())

    nmap_map: dict[str, list[dict]] | None = None
    if scan_ports and len(hosts) <= 64 and nmap_available():
        nmap_map = await asyncio.to_thread(run_nmap_scan, hosts, ports, 45.0)

    limiter = _RateLimiter(rate_limit_rps)
    sem = asyncio.Semaphore(max(1, min(int(max_concurrency or 8), len(hosts))))
    tasks: list[asyncio.Task] = []
    paused = False
    processed = 0
    client = None
    try:
        if httpx is not None:
            client = httpx.AsyncClient(timeout=6.0, follow_redirects=True, verify=False,
                                       headers={"User-Agent": "ASI-Mini/1.0 (read-only passive recon)"})
        for host in hosts:
            await limiter.wait()
            if window_end_dt and datetime.now(timezone.utc) >= window_end_dt:
                paused = True
                break
            nmap_ports = nmap_map.get(host.lower()) if nmap_map else None
            tasks.append(asyncio.create_task(
                _scan_one(host, sem, client, scan_ports=scan_ports, ports=ports,
                          signatures=signatures, nmap_ports=nmap_ports,
                          is_flaky=host.lower() in flaky_hosts)
            ))
            processed += 1
        results = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        if client is not None:
            await client.aclose()

    assets: list[dict] = []
    for host, result in zip(hosts[:processed], results):
        if isinstance(result, Exception):
            assets.append({"host": host, "ips": [], "cnames": [], "mx": [], "tls": _default_tls(),
                           "http": _default_http(), "open_ports": [], "sources": ["live_dns"],
                           "error": str(result)})
        elif isinstance(result, list):
            assets.extend(result)
        else:
            assets.append(result)

    consumed = start_cursor + len(assets)
    next_cursor = None if consumed >= total else consumed
    if paused:
        status = "paused_window_expired"
    elif next_cursor is not None:
        status = "paused_batch_limit"
    else:
        status = "completed"
    out = base_result(status, next_cursor, len(assets))
    out["subdomains"] = assets
    out["duration_sec"] = round(time.perf_counter() - started, 3)
    return out


async def fetch_subdomains(domain: str) -> list[str]:
    found = {domain}
    if httpx is not None:
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if r.status_code == 200:
                    for row in r.json():
                        for name in str(row.get("name_value", "")).splitlines():
                            host = name.strip().lower().lstrip("*.")
                            if host == domain or host.endswith(f".{domain}"):
                                found.add(host)
        except Exception:
            pass
    if len(found) <= 1:
        for prefix in FALLBACK_PREFIXES:
            found.add(f"{prefix}.{domain}")
    return sorted(found)[:20]


async def scan_domain(raw_domain: str, rate_limit_rps: float = 5.0,
                      signatures: list[dict] | None = None) -> dict:
    domain = clean_domain(raw_domain)
    if not domain:
        raise ValueError("A domain is required.")
    subdomains = await fetch_subdomains(domain)
    root = await asyncio.to_thread(resolve_root_dns, domain)
    result = await scan_targets(subdomains, domain=domain, rate_limit_rps=rate_limit_rps,
                                batch_limit=len(subdomains),
                                signatures=signatures if signatures is not None else DEFAULT_SIGNATURES,
                                dns_root=root)
    result["mode"] = "live"
    return result


# ---------------------------------------------------------------------------
# Importers
# ---------------------------------------------------------------------------
def _normalise_port(raw: Any) -> dict | None:
    if isinstance(raw, dict):
        try:
            port = int(raw.get("port") or raw.get("portid") or 0)
        except (TypeError, ValueError):
            return None
        if not port:
            return None
        return {
            "port": port, "protocol": raw.get("protocol") or "tcp",
            "service": raw.get("service") or SERVICE_NAMES.get(port, "unknown"),
            "product": raw.get("product") or "", "version": raw.get("version") or "",
        }
    text = str(raw or "").strip()
    if not text:
        return None
    match = re.match(r"^(\d{1,5})(?:/(\w+))?$", text)
    if not match:
        return None
    port = int(match.group(1))
    return {"port": port, "protocol": match.group(2) or "tcp",
            "service": SERVICE_NAMES.get(port, "unknown"), "product": "", "version": ""}


def _normalise_host(raw: Any, signatures: list[dict] | None = None) -> dict | None:
    if isinstance(raw, str):
        raw = {"host": raw}
    if not isinstance(raw, dict):
        return None
    host = raw.get("host") or raw.get("hostname") or raw.get("asset") or raw.get("name") or raw.get("ip")
    if not host:
        return None
    host = clean_domain(str(host)) if not _is_ip(str(host)) else str(host)
    ips = raw.get("ips") or raw.get("ip") or []
    if isinstance(ips, str):
        ips = [x.strip() for x in re.split(r"[,;\s]+", ips) if x.strip()]
    cnames = raw.get("cnames") or raw.get("cname") or []
    if isinstance(cnames, str):
        cnames = [x.strip() for x in re.split(r"[,;\s]+", cnames) if x.strip()]
    ports_raw = raw.get("open_ports") or raw.get("ports") or []
    if isinstance(ports_raw, str):
        ports_raw = [x for x in re.split(r"[,;\s]+", ports_raw) if x]
    open_ports = [p for p in (_normalise_port(x) for x in ports_raw) if p]
    http = _default_http()
    http.update({k: v for k, v in (raw.get("http") or {}).items() if k in http})
    for key in ("url", "status", "server", "x_powered_by", "title", "favicon_hash"):
        if raw.get(key) is not None:
            http[key] = raw[key]
    if raw.get("headers") and isinstance(raw["headers"], dict):
        http["headers"] = {str(k).lower(): str(v) for k, v in raw["headers"].items()}
    if http.get("server") and "server" not in http["headers"]:
        http["headers"]["server"] = str(http["server"])
    if http.get("x_powered_by") and "x-powered-by" not in http["headers"]:
        http["headers"]["x-powered-by"] = str(http["x_powered_by"])
    if not http.get("server") and http["headers"].get("server"):
        http["server"] = http["headers"]["server"]
    if not http.get("x_powered_by") and http["headers"].get("x-powered-by"):
        http["x_powered_by"] = http["headers"]["x-powered-by"]
    if raw.get("cookies"):
        http["cookies"] = raw["cookies"] if isinstance(raw["cookies"], list) else [str(raw["cookies"])]
    if raw.get("technologies"):
        http["technologies"] = raw["technologies"] if isinstance(raw["technologies"], list) else [str(raw["technologies"])]
    if http.get("url") or http.get("status"):
        http["reachable"] = True
        if not http.get("url"):
            http["url"] = f"https://{host}"
        if not http.get("scheme"):
            http["scheme"] = "https" if str(http["url"]).startswith("https") else "http"
    tls = _default_tls()
    tls.update({k: v for k, v in (raw.get("tls") or {}).items() if k in tls})
    for src, dst in (("tls_valid", "valid"), ("tls_days", "days_remaining"), ("tls_issuer", "issuer")):
        if raw.get(src) is not None:
            value = raw[src]
            if dst == "valid" and isinstance(value, str):
                value = value.strip().lower() in ("1", "true", "yes", "valid")
            if dst == "days_remaining":
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    value = None
            tls[dst] = value
    if tls.get("valid") is not None and tls.get("error") == "no_tls":
        tls["error"] = None if tls["valid"] else "certificate_invalid"
    asset = {
        "host": host, "ips": ips, "cnames": cnames, "mx": raw.get("mx") or [],
        "tls": tls, "http": http, "open_ports": open_ports,
        "sources": raw.get("sources") or ["import"],
    }
    if raw.get("matched_signatures"):
        asset["http"]["matched_signatures"] = raw["matched_signatures"]
    else:
        asset["http"]["technologies"] = detect_technologies(asset["http"], open_ports)
        asset["http"]["matched_signatures"] = evaluate_signatures(
            asset, signatures if signatures is not None else DEFAULT_SIGNATURES
        )
    return asset


def _import_result(target: str, mode: str, hosts: list[dict], dns_root: dict | None = None) -> dict:
    return {
        "target": target, "mode": mode, "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_sec": 0.0, "scan_status": "completed", "cursor": 0, "next_cursor": None,
        "total_hosts": len(hosts), "hosts_scanned": len(hosts), "rate_limit_rps": 0,
        "dns_root": dns_root or {"mx": [], "txt": [], "has_spf": True, "has_dmarc": True},
        "subdomains": hosts,
    }


def parse_nmap_xml(xml_text: str, filename: str = "internal-net.xml",
                   signatures: list[dict] | None = None) -> dict:
    sigs = signatures if signatures is not None else DEFAULT_SIGNATURES
    try:
        root = ET.fromstring((xml_text or "").strip())
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap XML: {exc}")
    hosts: list[dict] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue
        ips = [a.attrib["addr"] for a in host_el.findall("address")
               if a.attrib.get("addrtype") in ("ipv4", "ipv6")]
        name_el = host_el.find("./hostnames/hostname")
        label = name_el.attrib.get("name") if name_el is not None else (ips[0] if ips else "unknown-host")
        open_ports = []
        for port_el in host_el.findall("./ports/port"):
            state = port_el.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            svc = port_el.find("service")
            open_ports.append({
                "port": int(port_el.attrib.get("portid", 0)),
                "protocol": port_el.attrib.get("protocol", "tcp"),
                "service": svc.attrib.get("name", "unknown") if svc is not None else "unknown",
                "product": svc.attrib.get("product", "") if svc is not None else "",
                "version": svc.attrib.get("version", "") if svc is not None else "",
            })
        http = _default_http()
        http["technologies"] = detect_technologies(http, open_ports)
        tls = _default_tls()
        tls["error"] = "nmap_import"
        asset = {"host": label, "ips": ips, "cnames": [], "mx": [], "tls": tls, "http": http,
                 "open_ports": open_ports, "sources": ["nmap"]}
        asset["http"]["matched_signatures"] = evaluate_signatures(asset, sigs)
        hosts.append(asset)
    if not hosts:
        raise ValueError("No active hosts found in Nmap XML.")
    return _import_result(filename or "internal-net.xml", "nmap_import", hosts)


def parse_structured_import(content: str, filename: str = "import.json",
                            signatures: list[dict] | None = None) -> dict:
    text = (content or "").strip()
    if not text:
        raise ValueError("Import content is empty.")
    stem = Path(filename or "import").stem
    looks_json = text.startswith("{") or text.startswith("[")
    if filename.lower().endswith(".json") or looks_json:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"Invalid JSON import: {exc}")
        dns_root = None
        if isinstance(data, dict):
            target = data.get("target") or data.get("domain") or stem
            dns_root = data.get("dns_root")
            raw_hosts = data.get("subdomains") or data.get("hosts") or data.get("assets") or data.get("results") or []
        elif isinstance(data, list):
            target, raw_hosts = stem, data
        else:
            raise ValueError("JSON import must be an object or a list of hosts.")
        hosts = [h for h in (_normalise_host(x, signatures) for x in raw_hosts) if h]
        if not hosts:
            raise ValueError("No hosts found in JSON import.")
        return _import_result(str(target), "json_import", hosts, dns_root)
    try:
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        fields = [str(f or "").strip().lower() for f in (reader.fieldnames or [])]
    except Exception as exc:
        raise ValueError(f"Invalid CSV import: {exc}")
    if not rows or not fields:
        raise ValueError("CSV import needs a header row and at least one data row.")
    if not any(f in fields for f in ("host", "hostname", "asset", "ip")):
        raise ValueError("CSV import requires a host/hostname/asset/ip column.")
    grouped: dict[str, dict] = {}
    for row in rows:
        clean = {str(k or "").strip().lower(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
        host = clean.get("host") or clean.get("hostname") or clean.get("asset") or clean.get("ip")
        if not host:
            continue
        host = str(host)
        item = grouped.setdefault(host.lower(), {"host": host, "ips": [], "open_ports": [],
                                                 "cnames": [], "technologies": []})
        ip = clean.get("ip") or clean.get("ips")
        if ip:
            item["ips"].extend(x.strip() for x in re.split(r"[,;\s]+", str(ip)) if x.strip())
        cname = clean.get("cname") or clean.get("cnames")
        if cname:
            item["cnames"].extend(x.strip() for x in re.split(r"[,;\s]+", str(cname)) if x.strip())
        port = _normalise_port({"port": clean.get("port"), "protocol": clean.get("protocol"),
                                "service": clean.get("service"), "product": clean.get("product"),
                                "version": clean.get("version")})
        if port and port["port"]:
            item["open_ports"].append(port)
        for key in ("url", "status", "server", "x_powered_by", "title", "favicon_hash",
                    "tls_valid", "tls_days", "tls_issuer", "cookies"):
            if clean.get(key) not in (None, ""):
                item[key] = clean[key]
        tech = clean.get("technologies")
        if tech:
            item["technologies"].extend(x.strip() for x in re.split(r"[,;|]+", str(tech)) if x.strip())
    hosts = [h for h in (_normalise_host(x, signatures) for x in grouped.values()) if h]
    if not hosts:
        raise ValueError("No hosts found in CSV import.")
    return _import_result(stem, "csv_import", hosts)


# ---------------------------------------------------------------------------
# Demo datasets
# ---------------------------------------------------------------------------
def _demo_tls(valid: bool | None, days: int | None, issuer: str | None, error: str | None = None) -> dict:
    expires = None
    if days is not None:
        expires = datetime.fromtimestamp(time.time() + days * 86400, tz=timezone.utc).isoformat()
    return {"valid": valid, "days_remaining": days, "issuer": issuer, "subject": None,
            "expires_at": expires, "error": error}


def _demo_http(host: str, *, reachable: bool = True, scheme: str = "https", status: int = 200,
               title: str = "", server: str | None = None, powered: str | None = None,
               cookies: list[str] | None = None, body: str = "", paths: dict | None = None,
               missing: list[str] | None = None, footer_version: str | None = None) -> dict:
    http = _default_http()
    if not reachable:
        return http
    headers = {}
    if server:
        headers["server"] = server
    if powered:
        headers["x-powered-by"] = powered
    missing = missing if missing is not None else list(SEC_HEADERS)
    for name in SEC_HEADERS:
        if name not in missing:
            headers[name] = "configured"
    http.update({
        "reachable": True, "url": f"{scheme}://{host}", "scheme": scheme, "status": status,
        "title": title or None, "server": server, "x_powered_by": powered, "headers": headers,
        "cookies": cookies or [], "redirects": [], "favicon_hash": hashlib.sha256(host.encode()).hexdigest()[:16],
        "missing_headers": missing, "paths": paths or {}, "body_snippet": body,
        "footer_version": footer_version,
    })
    return http


def _demo_asset(host: str, *, ips: list[str] | None = None, cnames: list[str] | None = None,
                tls: dict | None = None, http: dict | None = None,
                open_ports: list[dict] | None = None) -> dict:
    asset = {"host": host, "ips": ips or [], "cnames": cnames or [], "mx": [],
             "tls": tls or _default_tls(), "http": http or _default_http(),
             "open_ports": open_ports or [], "sources": ["demo"]}
    asset["http"]["technologies"] = detect_technologies(asset["http"], asset["open_ports"])
    asset["http"]["matched_signatures"] = evaluate_signatures(asset)
    return asset


def get_demo_scan(raw_domain: str = "agh-infra.demo", variant: int = 1,
                  signatures: list[dict] | None = None) -> dict:
    d = clean_domain(raw_domain) or "agh-infra.demo"
    try:
        variant = int(variant)
    except (TypeError, ValueError):
        variant = 1
    variant = 2 if variant == 2 else 1

    hosts: list[dict] = [
        _demo_asset(
            d, ips=["149.156.10.10"],
            tls=_demo_tls(True, 140, "Let's Encrypt"),
            http=_demo_http(d, title="AGH Infrastructure Portal", server="nginx",
                            paths={"/version": {"status": 200}}, missing=["content-security-policy"]),
        ),
        _demo_asset(
            f"admin.{d}", ips=["149.156.10.22"],
            tls=_demo_tls(True, 5, "Let's Encrypt"),
            http=_demo_http(f"admin.{d}", title="Administration Console", server="Apache/2.4.49 (Unix)",
                            powered="PHP/7.4.3", cookies=["PHPSESSID"],
                            paths={"/admin": {"status": 200}, "/login": {"status": 200}},
                            footer_version="Apache/2.4.49"),
        ),
        _demo_asset(
            f"dev-api.{d}", ips=["149.156.10.45"],
            tls=_demo_tls(False, None, None, "CERTIFICATE_VERIFY_FAILED"),
            http=_demo_http(f"dev-api.{d}", scheme="http", title="Dev API",
                            server="Werkzeug/2.0.1 Python/3.8",
                            paths={"/admin": {"status": 404}, "/login": {"status": 200}}),
        ),
        _demo_asset(
            f"staging.{d}", ips=[], cnames=["old-app-test.azurewebsites.net."],
            tls=_default_tls(), http=_default_http(),
        ),
        _demo_asset(
            f"vpn.{d}", ips=["149.156.10.99"],
            tls=_demo_tls(True, 12, "DigiCert"),
            http=_demo_http(f"vpn.{d}", title="SSL VPN Portal", server="Cisco-ASA",
                            missing=["content-security-policy", "x-frame-options"]),
        ),
    ]

    if variant == 1:
        hosts.append(_demo_asset(
            f"legacy.{d}", ips=["149.156.10.77"],
            tls=_demo_tls(True, 90, "DigiCert"),
            http=_demo_http(f"legacy.{d}", title="Legacy Intranet", server="Microsoft-IIS/10.0"),
            open_ports=[
                {"port": 445, "protocol": "tcp", "service": "microsoft-ds",
                 "product": "Windows SMB", "version": ""},
                {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server",
                 "product": "Microsoft Terminal Services", "version": ""},
            ],
        ))
    else:
        # Same hostname remains in DNS, but the service went offline between runs.
        hosts.append(_demo_asset(
            f"legacy.{d}", ips=["149.156.10.77"],
            tls=_default_tls(), http=_default_http(),
        ))
        # New shadow WordPress + Redis host that did not exist in the first run.
        hosts.append(_demo_asset(
            f"shop.{d}", ips=["149.156.10.120"],
            tls=_demo_tls(True, 30, "Let's Encrypt"),
            http=_demo_http(
                f"shop.{d}", title="AGH Campus Shop", server="nginx", powered="PHP/8.1",
                cookies=["PHPSESSID"], body="<html><link href='/wp-content/themes/shop.css'>WordPress</html>",
                paths={"/admin": {"status": 200}, "/login": {"status": 200}},
                missing=["content-security-policy", "x-frame-options"],
                footer_version="WordPress 6.4.2",
            ),
            open_ports=[{"port": 6379, "protocol": "tcp", "service": "redis",
                         "product": "Redis key-value store", "version": "6.2.6"}],
        ))

    if signatures is not None:
        for asset in hosts:
            asset["http"]["matched_signatures"] = evaluate_signatures(asset, signatures)

    return {
        "target": d, "mode": "demo", "variant": variant,
        "scanned_at": datetime.now(timezone.utc).isoformat(), "duration_sec": 2.7,
        "scan_status": "completed", "cursor": 0, "next_cursor": None,
        "total_hosts": len(hosts), "hosts_scanned": len(hosts), "rate_limit_rps": 5.0,
        "dns_root": {"mx": [f"10 mail.{d}."], "txt": ["v=spf1 include:_spf.demo ~all"],
                     "ns": [f"ns1.{d}"], "spf": "v=spf1 include:_spf.demo ~all",
                     "dmarc": None, "has_spf": True, "has_dmarc": False},
        "subdomains": hosts,
    }
