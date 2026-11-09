#!/usr/bin/env python3
"""
Functional test for the access log over HTTP/2 and HTTP/1.1, whatever the upstream's framing:

  - every request is logged once, its protocol said: over HTTP/2 a response whose body came
    chunked from the upstream and went on as it came (the upstream compressed it, or the client
    asked for none) ended its stream as it was flushed and was never logged (rctuners.com's
    HTTP/2 requests, 2026-11-09);
  - the body reaches the client whole either way.

Needs curl with HTTP/2.

    python3 tests/accesslog_test.py        # from the repository root
"""
import gzip
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.abspath(os.path.join("tests", "tmp", "accesslog"))
shutil.rmtree(TMP, ignore_errors=True)
os.makedirs(os.path.join(TMP, "storage"))

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
HTTP, HTTPS = 9975, 9976
BODY = b"hello from the backend " * 40
PASS = FAIL = 0


def check(cond, name, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   - {name}")
    else:
        FAIL += 1
        print(f"  FAIL - {name}")
        if detail:
            print(f"         {str(detail)[:600]}")


def backend(port, gzips, chunked):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = BODY
            self.send_response(200)
            if gzips and "gzip" in (self.headers.get("Accept-Encoding") or ""):
                body = gzip.compress(body)
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Type", "text/html")
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for i in range(0, len(body), 100):
                    part = body[i:i + 100]
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# The upstreams: chunked or with a length, compressing or not.
SITES = {
    "chunked-gz": (9977, True, True),
    "chunked": (9978, False, True),
    "length-gz": (9979, True, False),
    "length": (9980, False, False),
}
for port in [HTTP, HTTPS] + [p for p, _, _ in SITES.values()]:
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", port)) == 0:
            print(f"port {port} is already in use by another program; free it and re-run")
            sys.exit(1)
servers = [backend(p, gz, ch) for p, gz, ch in SITES.values()]

cfg = os.path.join(TMP, "Limerfile")
with open(cfg, "w") as f:
    f.write(f"""{{
    http_port {HTTP}
    https_port {HTTPS}
    storage {TMP}/storage
    workers 2
    log_level info
}}
""")
    for name, (port, _, _) in SITES.items():
        f.write(f"""
{name}.localhost {{
    tls internal
    encode zstd gzip
    log {{
        output file {TMP}/{name}.log
        format json
    }}
    reverse_proxy 127.0.0.1:{port}
}}
""")

proc = subprocess.Popen([BIN, "run", "-c", cfg], stdout=subprocess.DEVNULL, stderr=open(os.path.join(TMP, "limer.log"), "w"))
try:
    for _ in range(100):
        r = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--resolve", f"length.localhost:{HTTPS}:127.0.0.1",
                            f"https://length.localhost:{HTTPS}/up"], capture_output=True, text=True)
        if r.stdout == "200":
            break
        time.sleep(0.1)
    for name in SITES:
        open(os.path.join(TMP, f"{name}.log"), "w").close()
    asked = []
    for name in SITES:
        for proto in ("--http1.1", "--http2"):
            for ae in ("gzip", "identity"):
                path = f"/?p={proto[2:]}&ae={ae}"
                asks = ["--compressed"] if ae == "gzip" else ["-H", "Accept-Encoding: identity"]
                out = subprocess.run(["curl", "-sk", proto, *asks, "--resolve", f"{name}.localhost:{HTTPS}:127.0.0.1",
                                      f"https://{name}.localhost:{HTTPS}{path}"], capture_output=True)
                check(out.stdout == BODY, f"{name} {proto} {ae}: the body arrives whole", out.stdout[:80])
                asked.append((name, proto, path))
    time.sleep(0.5)
    for name in SITES:
        lines = [json.loads(l.split(" ", 1)[1]) for l in open(os.path.join(TMP, f"{name}.log")) if l.strip()]
        for (n, proto, path) in [a for a in asked if a[0] == name]:
            want = "HTTP/2.0" if proto == "--http2" else "HTTP/1.1"
            got = [l for l in lines if l["uri"] == path]
            check(len(got) == 1 and got[0]["proto"] == want and got[0]["status"] == 200,
                  f"{name} {proto} {path}: logged once, as {want}", got)
finally:
    proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
    for s in servers:
        s.shutdown()

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
