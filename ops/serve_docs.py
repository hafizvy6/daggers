#!/usr/bin/env python3
"""Serve the whole repo (docs/ + web/) for the design-system page and README preview."""
import http.server, socketserver, sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8090

class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ROOT), **kw)
    def log_message(self, *a):  # quiet
        pass

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

with S(("0.0.0.0", PORT), H) as httpd:
    print(f"repo root on http://0.0.0.0:{PORT}  (docs/design-system.html, README.md)")
    httpd.serve_forever()
