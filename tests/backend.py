#!/usr/bin/env python3
"""Small test upstream: identifies itself and echoes request details as JSON.

Usage: backend.py PORT NAME [--slow SECONDS] [--fail-health]
Endpoints:
  /healthz      -> 200 "ok" (or 503 with --fail-health)
  /echo         -> JSON with name, method, path, headers, body
  /chunked      -> chunked response body
  /nolength     -> close-delimited response body (HTTP/1.0 style)
  /slow         -> sleeps --slow seconds before answering
  /status/NNN   -> responds with status NNN
  /big          -> 3 MiB response
  /ws           -> WebSocket-style 101 upgrade, echoes raw bytes back
  anything else -> text "hello from NAME"
"""
import json
import sys
import time
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
NAME = sys.argv[2]
SLOW = 0.0
FAIL_HEALTH = False
TLS = None
args = sys.argv[3:]
while args:
    a = args.pop(0)
    if a == "--slow":
        SLOW = float(args.pop(0))
    elif a == "--fail-health":
        FAIL_HEALTH = True
    elif a == "--tls":
        TLS = (args.pop(0), args.pop(0))  # cert, key


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, status, body, ctype="text/plain", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Backend", NAME)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD" and status not in (204, 304):
            self.wfile.write(body)

    def handle_any(self):
        body = self._body()
        path = self.path.split("?")[0]
        if path == "/healthz":
            if FAIL_HEALTH:
                self._send(503, b"unhealthy")
            else:
                self._send(200, b"ok")
        elif path == "/echo":
            doc = {
                "name": NAME,
                "method": self.command,
                "path": self.path,
                "headers": {k: v for k, v in self.headers.items()},
                "body": body.decode("utf-8", "replace"),
                "body_len": len(body),
            }
            self._send(200, json.dumps(doc).encode(), "application/json")
        elif path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("X-Backend", NAME)
            self.end_headers()
            for part in [b"alpha-", b"beta-", b"gamma"]:
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        elif path == "/nolength":
            self.close_connection = True
            self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Backend: " + NAME.encode() +
                             b"\r\nConnection: close\r\n\r\nclose-delimited body from " + NAME.encode())
        elif path == "/slow":
            time.sleep(SLOW)
            self._send(200, b"slow response from " + NAME.encode())
        elif path.startswith("/status/"):
            code = int(path.rsplit("/", 1)[1])
            self._send(code, ("status %d from %s" % (code, NAME)).encode())
        elif path == "/big":
            self._send(200, (NAME + "|").encode() * (3 * 1024 * 1024 // (len(NAME) + 1)))
        elif path == "/ws":
            if self.headers.get("Upgrade", "").lower() != "websocket":
                self._send(400, b"not an upgrade")
                return
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("X-Backend", NAME)
            self.end_headers()
            self.wfile.flush()
            # raw echo loop with a prefix until the client closes
            self.connection.settimeout(5)
            try:
                while True:
                    data = self.connection.recv(4096)
                    if not data:
                        break
                    self.connection.sendall(b"echo:" + data)
            except socket.timeout:
                pass
            self.close_connection = True
        elif path == "/drop":
            # close without responding (simulates a crash mid-request)
            self.close_connection = True
            self.connection.close()
        else:
            self._send(200, b"hello from " + NAME.encode())

    do_GET = handle_any
    do_POST = handle_any
    do_PUT = handle_any
    do_DELETE = handle_any
    do_HEAD = handle_any
    do_PATCH = handle_any


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # clients (and the proxy) are expected to drop connections in tests


if __name__ == "__main__":
    srv = Server(("127.0.0.1", PORT), Handler)
    if TLS:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(TLS[0], TLS[1])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
