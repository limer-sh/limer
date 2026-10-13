#!/usr/bin/env python3
"""Backend for cache tests: a hit counter and per-path caching headers.

    python3 tests/cacheback.py PORT

Each response body embeds the upstream hit count so a client can tell a
cache HIT (count unchanged) from a MISS (count incremented). Paths:
  /maxage     Cache-Control: max-age=2
  /smaxage    Cache-Control: s-maxage=2, max-age=0
  /etag       ETag "v1" + max-age=1; answers 304 to If-None-Match "v1"
  /vary       Vary: X-Variant, max-age=10; body includes the variant
  /nostore    Cache-Control: no-store
  /private    Cache-Control: private, max-age=60
  /setcookie  max-age=60 + Set-Cookie (must not be cached)
  /nocache    Cache-Control: no-cache + ETag "n1"
  /plain      no caching headers
"""
import sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
HITS = 0

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _send(self, code, body, extra):
        self.send_response(code)
        for k, v in extra:
            self.send_header(k, v)
        if code != 304:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if code != 304 and self.command != "HEAD":
            self.wfile.write(body)
    def do_HEAD(self): self.do_GET()
    def do_GET(self):
        global HITS
        with LOCK:
            HITS += 1
            n = HITS
        p = self.path.split("?")[0]
        if p == "/maxage":
            self._send(200, b"body-%d" % n, [("Cache-Control", "max-age=2"), ("Content-Type", "text/plain")])
        elif p == "/smaxage":
            self._send(200, b"body-%d" % n, [("Cache-Control", "s-maxage=2, max-age=0")])
        elif p == "/etag":
            if self.headers.get("If-None-Match") == '"v1"':
                self._send(304, b"", [("ETag", '"v1"'), ("Cache-Control", "max-age=1")])
            else:
                self._send(200, b"etag-%d" % n, [("ETag", '"v1"'), ("Cache-Control", "max-age=1")])
        elif p == "/vary":
            v = self.headers.get("X-Variant", "none")
            self._send(200, ("variant=%s-%d" % (v, n)).encode(), [("Vary", "X-Variant"), ("Cache-Control", "max-age=10")])
        elif p == "/nostore":
            self._send(200, b"body-%d" % n, [("Cache-Control", "no-store")])
        elif p == "/private":
            self._send(200, b"body-%d" % n, [("Cache-Control", "private, max-age=60")])
        elif p == "/setcookie":
            self._send(200, b"body-%d" % n, [("Cache-Control", "max-age=60"), ("Set-Cookie", "s=1")])
        elif p == "/nocache":
            if self.headers.get("If-None-Match") == '"n1"':
                self._send(304, b"", [("ETag", '"n1"'), ("Cache-Control", "no-cache")])
            else:
                self._send(200, b"nocache-%d" % n, [("ETag", '"n1"'), ("Cache-Control", "no-cache")])
        elif p == "/large":
            self._send(200, (b"LARGE " * 400) + b"%d" % n, [("Cache-Control", "max-age=5"), ("Content-Type", "text/plain")])
        elif p == "/hits":
            self._send(200, b"%d" % n, [("Cache-Control", "no-store")])
        else:
            self._send(200, b"plain-%d" % n, [])

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
