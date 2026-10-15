#!/usr/bin/env python3
"""
Functional test for pool broadcasts (`discover <name> { broadcast <path> }` +
POST /broadcast).

Two backends register into a `discover` pool that has a broadcast path; a POST
to the admin API's /broadcast reaches both as POST <path>, body and content type
intact. Covers the refusals too: unknown pools, pools without a broadcast path,
a missing secret, and methods other than POST.

    python3 tests/broadcast_test.py        # from the repository root
"""
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "broadcast")
os.makedirs(TMP, exist_ok=True)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
SECRET = "broadcast-secret-0123456789abcdef"
ADMIN, SITE, PLAIN = 9941, 9942, 9943
B1, B2 = 9944, 9945
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
            print(f"         {detail}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        out = str(self.server.server_port).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        self.server.got.put((self.path, self.headers.get("Content-Type"),
                             self.headers.get("X-Limer-Broadcast"), body.decode()))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


def serve(port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.got = queue.Queue()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def wait_tcp(port, tries=200):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def admin(method, path, body=None, secret=SECRET, ctype="application/json"):
    headers = {"Content-Type": ctype}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    req = urllib.request.Request(f"http://127.0.0.1:{ADMIN}{path}", method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def received(srv, timeout=3):
    try:
        return srv.got.get(timeout=timeout)
    except queue.Empty:
        return None


def main():
    b1, b2 = serve(B1), serve(B2)
    cfg = os.path.join(TMP, "Limerfile")
    with open(cfg, "w") as f:
        f.write(f"""{{
    admin 127.0.0.1:{ADMIN} {{
        secret {SECRET}
    }}
    log_level warn
    storage {TMP}/storage
    pidfile {TMP}/limer.pid
}}
127.0.0.1:{SITE} {{
    reverse_proxy {{
        discover app {{
            allow 127.0.0.0/8
            broadcast /_announce
        }}
    }}
}}
127.0.0.1:{PLAIN} {{
    reverse_proxy {{
        discover quiet {{
            allow 127.0.0.0/8
        }}
    }}
}}
""")
    log = open(os.path.join(TMP, "limer.log"), "w")
    p = subprocess.Popen([BIN, "run", "-c", cfg], stdout=subprocess.DEVNULL, stderr=log)
    try:
        if not (wait_tcp(ADMIN) and wait_tcp(SITE)):
            raise SystemExit("limer did not come up")
        print("broadcast")
        for port in (B1, B2):
            s, j = admin("POST", f"/register?service=app&port={port}&ttl=30")
            check(s == 200, f"backend {port} registers", f"{s} {j}")

        msg = json.dumps({"topics": ["db:orders"], "from": "a1"}).encode()
        s, j = admin("POST", "/broadcast?service=app", msg)
        check(s == 200 and j.get("members") == 2, "a broadcast goes to every member", f"{s} {j}")
        for srv, port in ((b1, B1), (b2, B2)):
            got = received(srv)
            check(got == ("/_announce", "application/json", "app", msg.decode()),
                  f"backend {port} gets POST <path> with the body, content type and pool", got)

        # a member that just registered gets the next one, without waiting for a refresh tick
        b3 = serve(B2 + 2)
        admin("POST", f"/register?service=app&port={B2 + 2}&ttl=30")
        s, j = admin("POST", "/broadcast?service=app", b"x", ctype="text/plain")
        check(s == 200 and j.get("members") == 3, "a new member is included at once", j)
        got = received(b3)
        check(got is not None and got[1] == "text/plain" and got[3] == "x", "the new member receives it", got)
        received(b1), received(b2)

        s, j = admin("POST", "/broadcast?service=nope", b"{}")
        check(s == 404, "an unknown pool is refused", f"{s} {j}")
        s, j = admin("POST", "/broadcast?service=quiet", b"{}")
        check(s == 404 and "broadcast" in j.get("error", ""), "a pool without a broadcast path is refused", f"{s} {j}")
        s, j = admin("POST", "/broadcast?service=app", b"{}", secret="wrong-secret-0123456789abcdef")
        check(s == 401, "a wrong secret is refused", f"{s} {j}")
        s, j = admin("GET", "/broadcast?service=app")
        check(s == 405, "only POST broadcasts", f"{s} {j}")
        check(received(b1, 0.5) is None, "refused broadcasts reach nobody")

        # a member that has gone away does not stop the others getting it
        b2.shutdown()
        b2.server_close()
        s, j = admin("POST", "/broadcast?service=app", b"after")
        got = received(b1)
        check(s == 200 and got is not None and got[3] == "after", "a dead member does not stop the broadcast", f"{s} {j} {got}")
        s, j = admin("GET", "/health")
        check(s == 200, "limer is still healthy afterwards", f"{s} {j}")

        text = open(os.path.join(TMP, "limer.log")).read()
        check("AddressSanitizer" not in text and "runtime error" not in text, "no sanitizer reports")
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()

    print(f"\nbroadcast tests: passed {PASS}, failed {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
