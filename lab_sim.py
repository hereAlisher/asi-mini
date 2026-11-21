"""Lab Target Simulator — stdlib-only local HTTP servers for jury demos.

Launch three vulnerable-looking services on 127.0.0.1 so ASI Mini can scan them
live and demonstrate fingerprinting, flaky-host detection, and change drift.

Usage:
    .\\.venv\\Scripts\\python.exe lab_sim.py

Services:
    Port 9001 — Fake CMS (WordPress, PHPSESSID, /admin 200, footer version)
    Port 9002 — Staging API (Werkzeug/2.0.1, /version 200, "Staging Sandbox")
    Port 9003 — Flaky IoT/Edge (Cisco-ASA, alternates 200 / 503 per request)

Press Ctrl+C to stop all servers.
"""
from __future__ import annotations

import http.server
import socketserver
import threading
import time

PORTS = [9001, 9002, 9003]
_flaky_9003_state = {"count": 0}


class LabCMSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Lab CMS Admin</h1><p>WordPress wp-admin</p>")
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "PHPSESSID=lab123; Path=/")
            self.end_headers()
            self.wfile.write(
                b"<html><head><title>Lab CMS - WordPress</title></head>"
                b"<body><h1>Welcome to Lab CMS</h1>"
                b"<footer>Powered by LabCMS v2.1.4</footer></body></html>"
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class LabStagingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/version":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"version": "2.0.1", "env": "staging"}')
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Werkzeug/2.0.1 Python/3.8")
            self.end_headers()
            self.wfile.write(
                b"<html><head><title>Staging Sandbox</title></head>"
                b"<body><h1>Staging Sandbox API</h1></body></html>"
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class LabFlakyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        _flaky_9003_state["count"] += 1
        if _flaky_9003_state["count"] % 2 == 0:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Cisco-ASA")
            self.end_headers()
            self.wfile.write(b"<html><body>IoT Edge Device</body></html>")
        else:
            self.send_response(503)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Server", "Cisco-ASA")
            self.end_headers()
            self.wfile.write(b"Service Unavailable")

    def log_message(self, format, *args):
        pass


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def _serve(port: int, handler_cls, stop_event: threading.Event):
    with ReusableTCPServer(("127.0.0.1", port), handler_cls) as httpd:
        httpd.timeout = 0.5
        while not stop_event.is_set():
            httpd.handle_request()


def main():
    stop_event = threading.Event()
    servers = [
        (PORTS[0], LabCMSHandler, "LabCMS (WordPress)"),
        (PORTS[1], LabStagingHandler, "Staging API (Werkzeug)"),
        (PORTS[2], LabFlakyHandler, "Flaky IoT (Cisco-ASA)"),
    ]
    threads = []
    for port, handler, name in servers:
        t = threading.Thread(target=_serve, args=(port, handler, stop_event), daemon=True)
        t.start()
        threads.append(t)
        print(f"[+] {name} on http://127.0.0.1:{port}/")

    print("\nASI Mini Lab Simulator running. Press Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping lab simulator...")
        stop_event.set()
        for t in threads:
            t.join(timeout=2)
        print("[*] All lab servers stopped.")


if __name__ == "__main__":
    main()