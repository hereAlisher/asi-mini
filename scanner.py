import asyncio
import socket
import ssl
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import dns.resolver
import httpx

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
]
FALLBACK_PREFIXES = ["www", "mail", "dev", "staging", "admin", "api", "vpn", "test"]

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


def clean_domain(raw: str) -> str:
    d = raw.strip().lower().replace("https://", "").replace("http://", "")
    return d.split("/")[0].split(":")[0].strip(".")


async def fetch_subdomains(domain: str) -> list[str]:
    found = {domain}
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
        for p in FALLBACK_PREFIXES:
            found.add(f"{p}.{domain}")
    return sorted(found)[:20]


def _resolve_records(name: str, rtype: str) -> list[str]:
    try:
        res = dns.resolver.Resolver()
        res.lifetime = 3.0
        return [r.to_text().strip('"') for r in res.resolve(name, rtype)]
    except Exception:
        return []


def resolve_root_dns(domain: str) -> dict:
    mx = _resolve_records(domain, "MX")
    txt = _resolve_records(domain, "TXT")
    dmarc = _resolve_records(f"_dmarc.{domain}", "TXT")
    return {
        "mx": mx,
        "txt": txt[:5],
        "has_spf": any("v=spf1" in t.lower() for t in txt),
        "has_dmarc": any("v=dmarc1" in t.lower() for t in dmarc),
    }


def inspect_tls(host: str) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                exp_ts = ssl.cert_time_to_seconds(cert["notAfter"])
                days_left = int((exp_ts - time.time()) / 86400)
                issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "Unknown")
                return {"valid": True, "days_remaining": days_left, "issuer": issuer, "error": None}
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "days_remaining": None, "issuer": None, "error": str(e.reason)}
    except Exception:
        return {"valid": None, "days_remaining": None, "issuer": None, "error": "no_tls"}


async def inspect_http(host: str, client: httpx.AsyncClient) -> dict:
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}")
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return {
                "reachable": True,
                "url": str(r.url),
                "status": r.status_code,
                "server": hdrs.get("server"),
                "x_powered_by": hdrs.get("x-powered-by"),
                "missing_headers": [h for h in SEC_HEADERS if h not in hdrs],
            }
        except Exception:
            continue
    return {"reachable": False, "url": None, "status": None, "server": None, "x_powered_by": None, "missing_headers": []}


async def scan_host(host: str, sem: asyncio.Semaphore, client: httpx.AsyncClient) -> dict:
    async with sem:
        ips, cnames, tls, http = await asyncio.gather(
            asyncio.to_thread(_resolve_records, host, "A"),
            asyncio.to_thread(_resolve_records, host, "CNAME"),
            asyncio.to_thread(inspect_tls, host),
            inspect_http(host, client),
        )
        return {"host": host, "ips": ips, "cnames": cnames, "tls": tls, "http": http, "open_ports": []}


async def scan_domain(raw_domain: str) -> dict:
    domain = clean_domain(raw_domain)
    subdomains, dns_root = await asyncio.gather(
        fetch_subdomains(domain),
        asyncio.to_thread(resolve_root_dns, domain),
    )
    sem = asyncio.Semaphore(10)
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
        results = await asyncio.gather(*(scan_host(h, sem, client) for h in subdomains))
    return {
        "target": domain,
        "mode": "live",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "dns_root": dns_root,
        "subdomains": results,
    }


def parse_nmap_xml(xml_text: str, filename: str = "internal-net.xml") -> dict:
    try:
        root = ET.fromstring(xml_text.strip())
    except ET.ParseError as e:
        raise ValueError(f"Invalid Nmap XML: {e}")

    hosts = []
    for h_el in root.findall("host"):
        st = h_el.find("status")
        if st is not None and st.attrib.get("state") != "up":
            continue
        ips = [a.attrib["addr"] for a in h_el.findall("address") if a.attrib.get("addrtype") in ("ipv4", "ipv6")]
        hname_el = h_el.find("./hostnames/hostname")
        host_label = hname_el.attrib.get("name") if hname_el is not None else (ips[0] if ips else "unknown-host")

        open_ports = []
        for p_el in h_el.findall("./ports/port"):
            p_state = p_el.find("state")
            if p_state is None or p_state.attrib.get("state") != "open":
                continue
            svc = p_el.find("service")
            open_ports.append({
                "port": int(p_el.attrib.get("portid", 0)),
                "protocol": p_el.attrib.get("protocol", "tcp"),
                "service": svc.attrib.get("name", "unknown") if svc is not None else "unknown",
                "product": svc.attrib.get("product", "") if svc is not None else "",
                "version": svc.attrib.get("version", "") if svc is not None else "",
            })

        hosts.append({
            "host": host_label,
            "ips": ips,
            "cnames": [],
            "tls": {"valid": None, "days_remaining": None, "issuer": None, "error": "nmap_import"},
            "http": {"reachable": False, "url": None, "status": None, "server": None, "x_powered_by": None, "missing_headers": []},
            "open_ports": open_ports,
        })

    if not hosts:
        raise ValueError("No active hosts found in Nmap XML.")

    return {
        "target": filename,
        "mode": "nmap_import",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "dns_root": {"mx": [], "txt": [], "has_spf": True, "has_dmarc": True},
        "subdomains": hosts,
    }


def get_demo_scan(raw_domain: str = "agh-infra.demo") -> dict:
    d = clean_domain(raw_domain) or "agh-infra.demo"
    return {
        "target": d,
        "mode": "demo",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "dns_root": {"mx": [f"10 mail.{d}."], "txt": ["v=spf1 include:_spf.demo ~all"], "has_spf": True, "has_dmarc": False},
        "subdomains": [
            {"host": d, "ips": ["149.156.10.10"], "cnames": [], "open_ports": [], "tls": {"valid": True, "days_remaining": 140, "issuer": "Let's Encrypt", "error": None}, "http": {"reachable": True, "url": f"https://{d}", "status": 200, "server": "nginx", "x_powered_by": None, "missing_headers": ["content-security-policy"]}},
            {"host": f"admin.{d}", "ips": ["149.156.10.22"], "cnames": [], "open_ports": [], "tls": {"valid": True, "days_remaining": 5, "issuer": "Let's Encrypt", "error": None}, "http": {"reachable": True, "url": f"https://admin.{d}/login", "status": 200, "server": "Apache/2.4.49 (Unix)", "x_powered_by": "PHP/7.4.3", "missing_headers": SEC_HEADERS}},
            {"host": f"dev-api.{d}", "ips": ["149.156.10.45"], "cnames": [], "open_ports": [], "tls": {"valid": False, "days_remaining": None, "issuer": None, "error": "CERTIFICATE_VERIFY_FAILED"}, "http": {"reachable": True, "url": f"http://dev-api.{d}", "status": 200, "server": "Werkzeug/2.0.1 Python/3.8", "x_powered_by": None, "missing_headers": SEC_HEADERS}},
            {"host": f"staging.{d}", "ips": [], "cnames": ["old-app-test.azurewebsites.net."], "open_ports": [], "tls": {"valid": None, "days_remaining": None, "issuer": None, "error": "no_tls"}, "http": {"reachable": False, "url": None, "status": None, "server": None, "x_powered_by": None, "missing_headers": []}},
            {"host": f"vpn.{d}", "ips": ["149.156.10.99"], "cnames": [], "open_ports": [], "tls": {"valid": True, "days_remaining": 12, "issuer": "DigiCert", "error": None}, "http": {"reachable": True, "url": f"https://vpn.{d}", "status": 200, "server": "Cisco-ASA", "x_powered_by": None, "missing_headers": ["content-security-policy", "x-frame-options"]}},
        ],
    }