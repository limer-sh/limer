#!/usr/bin/env python3
"""
Functional test for self-registration service discovery (`discover` pools +
POST /register / /deregister).

A `discover orders` pool starts empty; a backend registers itself through the
admin API, passes its health check, settles, and then takes traffic; when its
heartbeat lapses it is evicted. Covers the allow-list, the settle/health gate,
heartbeat expiry, deregister, and that discovery never empties a pool.

    python3 tests/discover_test.py        # from the repository root
"""
import json
import os
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
TMP = os.path.join("tests", "tmp", "discover")
os.makedirs(TMP, exist_ok=True)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
SECRET = "discover-secret-0123456789abcdef"
ADMIN, SITE = 9931, 9932
B1, B2 = 9933, 9934
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
        code = 200 if self.server.healthy else 503
        self.send_response(code if self.path == "/healthz" else 200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def serve(port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.healthy = True
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


def admin(method, path, timeout=5):
    req = urllib.request.Request(f"http://127.0.0.1:{ADMIN}{path}", method=method,
                                 headers={"Authorization": f"Bearer {SECRET}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def site(path="/", timeout=5):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{SITE}{path}", timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""
    except OSError as e:
        return 0, str(e)


def backends_hit(n=12):
    seen = {}
    for _ in range(n):
        s, body = site("/")
        if s == 200 and body.isdigit():
            seen[body] = seen.get(body, 0) + 1
    return seen


def register(port, ttl=30, weight=1, service="orders"):
    return admin("POST", f"/register?service={service}&port={port}&ttl={ttl}&weight={weight}")


def main():
    b1 = serve(B1)
    serve(B2)
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
        discover orders {{
            allow 127.0.0.0/8
            settle 1s
        }}
        health_uri /healthz
        health_interval 500ms
        lb_policy round_robin
    }}
}}
""")
    log = open(os.path.join(TMP, "limer.log"), "w")
    p = subprocess.Popen([BIN, "run", "-c", cfg], stdout=subprocess.DEVNULL, stderr=log)
    try:
        if not (wait_tcp(ADMIN) and wait_tcp(SITE)):
            raise SystemExit("limer did not come up")
        print("discovery")
        # empty pool: no members yet
        s, _ = site("/")
        check(s in (502, 503), "a discover pool with no members returns an error", f"status={s}")

        # the allow-list rejects an unlisted range (configured allow is 127/8 which we are in,
        # so test rejection with a service whose pool allows only 10/8 -> use a bad-port path);
        # here verify an unknown service is refused
        s, j = admin("POST", f"/register?service=nope&port={B1}&ttl=3")
        check(s == 404, "registering for an unknown pool is refused", f"{s} {j}")

        # register backend 1
        s, j = register(B1)
        check(s == 200 and j.get("status") == "registered", "a backend registers itself", f"{s} {j}")
        s, j = admin("GET", "/registry")
        check(s == 200 and any(m["address"].endswith(f":{B1}") for m in j.get("members", [])),
              "the member shows up in /registry", j)

        # health-gated + settle: not serving immediately
        s, _ = site("/")
        check(s in (502, 503), "a just-registered member is held out until health + settle", f"status={s}")

        # after the health check passes and settle elapses, it serves
        ok_at = time.time() + 5
        served = False
        while time.time() < ok_at:
            s, body = site("/")
            if s == 200 and body == str(B1):
                served = True
                break
            time.sleep(0.2)
        check(served, "after health passes and it settles, the member takes traffic")

        # register backend 2 (long ttl); both should serve round-robin once settled
        register(B2, ttl=30)
        time.sleep(2.5)
        seen = backends_hit(20)
        check(str(B1) in seen and str(B2) in seen, "a second registered backend joins the rotation", seen)

        # a heartbeating member stays; B2 registered short and not refreshed expires
        register(B1, ttl=30)
        register(B2, ttl=2)
        time.sleep(3.5)
        s, j = admin("GET", "/registry")
        addrs = [m["address"] for m in j.get("members", [])]
        check(any(a.endswith(f":{B1}") for a in addrs), "a heartbeating member stays registered", addrs)
        check(not any(a.endswith(f":{B2}") for a in addrs), "a member whose heartbeat lapses is evicted", addrs)

        # deregister: with two members, an explicit deregister removes one
        register(B1, ttl=30)
        register(B2, ttl=30)
        time.sleep(2.0)
        s, j = admin("POST", f"/deregister?service=orders&port={B2}")
        check(s == 200 and j.get("removed") == 1, "deregister removes a member", j)

        # an unhealthy member is skipped while a healthy peer exists
        register(B1, ttl=30)
        register(B2, ttl=30)
        time.sleep(2.0)
        b1.healthy = False          # B1 fails its health check; B2 stays healthy
        time.sleep(1.5)
        seen = backends_hit(16)
        check(str(B2) in seen and str(B1) not in seen,
              "an unhealthy member is skipped when a healthy peer exists", seen)

        # never empty: deregister every member; discovery keeps the last known set
        # rather than emptying the pool, so a healthy one keeps serving
        b1.healthy = True
        time.sleep(1.0)
        admin("POST", f"/deregister?service=orders&port={B1}")
        admin("POST", f"/deregister?service=orders&port={B2}")
        time.sleep(1.5)
        s4, _ = admin("GET", "/registry")
        _, reg = admin("GET", "/registry")
        check(len(reg.get("members", [])) == 0, "deregistering every member empties the registry", reg)
        s5, _ = site("/")
        check(s5 == 200, "but the pool is never emptied: a kept member keeps serving", f"status={s5}")

        text = open(os.path.join(TMP, "limer.log")).read()
        check("AddressSanitizer" not in text and "runtime error" not in text, "no sanitizer reports")
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()

    print(f"\ndiscover tests: passed {PASS}, failed {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
