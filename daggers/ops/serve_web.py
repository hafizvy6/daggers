#!/usr/bin/env python3
"""WS3 dev helper — static server for web/ (parity with Cloudflare Pages).

  python3 ops/serve_web.py [port]      → http://localhost:8000
  /share?url=… lands on the shell (share-target contract); everything else is static.
This is a developer convenience, not a product artifact.
"""
import http.server, socketserver, sys, urllib.parse, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1] / "web"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ROOT), **kw)

    def translate_path(self, path):
        p = urllib.parse.urlparse(path).path
        return str(ROOT / "index.html") if p == "/share" else super().translate_path(path)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Service-Worker-Allowed", "/")
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("%s\n" % (fmt % args))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", PORT), Handler) as httpd:
        # 0.0.0.0 = listen on all interfaces; it is not a browsable URL.
        print(f"Daggers web  →  open http://localhost:{PORT}?mode=demo#/feed")
        print(f"              (bound 0.0.0.0:{PORT}, root: {ROOT})")
        httpd.serve_forever()
