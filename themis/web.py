"""A read-only page for Themis: recent events, what is known, the ignore rules.

    themis web [--port 8093]     127.0.0.1 only; nothing on the page can change anything
"""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import __version__, status
from .rules import SEVERITIES
from .store import Store

HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                               "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}
FILES = {"/": ("index.html", "text/html; charset=utf-8"), "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
         "/static/style.css": ("style.css", "text/css; charset=utf-8"),
         "/static/themis.svg": ("themis.svg", "image/svg+xml")}
ALLOWED_HOSTS = ("127.0.0.1", "localhost", "[::1]")


def make_handler(db: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"Themis/{__version__}"
        sys_version = ""

        def log_message(self, *a):
            pass

        def send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            for k, v in HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            if host not in ALLOWED_HOSTS:   # DNS rebinding: a web page must not read this through a name
                return self.send(400, b"bad host", "text/plain")
            u = urlparse(self.path)
            if u.path in FILES:
                name, ctype = FILES[u.path]
                return self.send(200, resources.files("themis").joinpath("static", name).read_bytes(), ctype)
            store = Store(db)
            if u.path == "/api/events":
                q = parse_qs(u.query)
                try:
                    days = min(max(float(q.get("days", ["7"])[0]), 0.1), 90)
                except ValueError:
                    return self.send(400, b'{"error": "bad days"}', "application/json")
                sev = q.get("min", ["low"])[0]
                if sev not in SEVERITIES:
                    return self.send(400, b'{"error": "bad severity"}', "application/json")
                data = store.events(since=time.time() - days * 86400, min_severity=sev, limit=500)
            elif u.path == "/api/overview":
                data = {**status.build(store), "usb": store.known("usb"), "ports": store.known("port"),
                        "services": len(store.known("unit")), "ignore": store.ignores()}
            else:
                return self.send(404, b'{"error": "not found"}', "application/json")
            return self.send(200, json.dumps(data).encode(), "application/json")

    return Handler


def serve(db: str, port: int) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(db))
    srv.daemon_threads = True
    return srv
