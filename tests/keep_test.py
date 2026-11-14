#!/usr/bin/env python3
"""
Servers in rotation stay in rotation through a reload, a restart and an upgrade.

A reload carries each upstream's health over from the old configuration: from the
pool of the same name, and else from any pool checking the same address alike (an
unnamed `reverse_proxy` pool is named after its place in its site, reverse_proxy<N>,
so a route added before it renamed it, and its members waited for a health check
and their settle again, the site answering 503 meanwhile). A restart or an upgrade
restores the registered members from <storage>/registry.json in rotation at once:
they were serving. A member that registers anew still waits for its health check
and settles.

    python3 tests/keep_test.py        # from the repository root
"""
import json
import os
import signal
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
TMP = os.path.join("tests", "tmp", "keep")
os.makedirs(TMP, exist_ok=True)

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./limer")
SECRET = "keep-secret-0123456789abcdef0123"
ADMIN, SITE = 9941, 9942
B1, B2 = 9943, 9944
PASS = FAIL = 0
CFG = os.path.join(TMP, "Limerfile")
PIDFILE = os.path.join(TMP, "limer.pid")


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

    def log_message(self, *a):
        pass


def serve(port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
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
        return e.code, {}
    except OSError:
        return 0, {}


def site(path="/", timeout=3):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{SITE}{path}", timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""
    except OSError as e:
        return 0, str(e)


def hammer(seconds, path="/"):
    """Ask every 30 ms for `seconds`: the answers' statuses and bodies, counted."""
    seen = {}
    end = time.time() + seconds
    while time.time() < end:
        s, body = site(path)
        key = f"{s} {body}" if s == 200 else str(s)
        seen[key] = seen.get(key, 0) + 1
        time.sleep(0.03)
    return seen


def only_200(seen):
    return bool(seen) and all(k.startswith("200 ") for k in seen)


def write_cfg(routes_before=""):
    # A long health interval and settle, so that waiting for them again would show.
    with open(CFG, "w") as f:
        f.write(f"""{{
    admin 127.0.0.1:{ADMIN} {{
        secret {SECRET}
    }}
    log_level info
    storage {TMP}/storage
    pidfile {PIDFILE}
}}
127.0.0.1:{SITE} {{
{routes_before}    reverse_proxy {{
        discover orders {{
            allow 127.0.0.0/8
            settle 2s
        }}
        health_uri /healthz
        health_interval 3s
        lb_policy round_robin
    }}
}}
""")


def start(log):
    p = subprocess.Popen([BIN, "run", "-c", CFG], stdout=subprocess.DEVNULL, stderr=log)
    if not (wait_tcp(ADMIN) and wait_tcp(SITE)):
        raise SystemExit("limer did not come up")
    return p


def stop(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()


def main():
    serve(B1)
    serve(B2)
    # (limer keeps its registry in `storage`, which it does not make.)
    os.makedirs(os.path.join(TMP, "storage"), exist_ok=True)
    if os.path.exists(os.path.join(TMP, "storage", "registry.json")):
        os.remove(os.path.join(TMP, "storage", "registry.json"))
    write_cfg()
    log = open(os.path.join(TMP, "limer.log"), "w")
    p = start(log)
    try:
        print("keeping servers in rotation")
        admin("POST", f"/register?service=orders&port={B1}&ttl=120")
        ok_at = time.time() + 8
        while time.time() < ok_at and site("/") != (200, str(B1)):
            time.sleep(0.1)
        check(site("/") == (200, str(B1)), "a registered member takes traffic once healthy and settled")

        # A reload that adds routes before the catch-all pool (renaming it reverse_proxy3), and
        # a new route whose pool draws on the same `discover`: both serve at once.
        write_cfg("""    route plain {
        match path /plain
        respond "plain" 200
    }
    route also {
        match path /also/*
        reverse_proxy {
            discover orders {
                allow 127.0.0.0/8
                settle 2s
            }
            health_uri /healthz
            health_interval 3s
        }
    }
""")
        r = subprocess.run([BIN, "reload", "-c", CFG], capture_output=True, text=True, timeout=30)
        check(r.returncode == 0, "the reload is taken", r.stdout + r.stderr)
        seen = hammer(2.5)
        check(only_200(seen) and seen.get(f"200 {B1}"), "after a reload that renames its pool, its member serves throughout", seen)
        seen = hammer(1.0, "/also/x")
        check(only_200(seen), "a new route's pool on the same discover serves at once, its members' health carried", seen)
        check(site("/plain") == (200, "plain"), "the new routes are in effect")

        # A newcomer still waits for its health check and settle.
        admin("POST", f"/register?service=orders&port={B2}&ttl=120")
        seen = hammer(0.8)
        check(only_200(seen) and f"200 {B2}" not in seen, "a member registered anew is held out at first", seen)
        time.sleep(5.5)
        seen = hammer(1.0)
        check(seen.get(f"200 {B1}") and seen.get(f"200 {B2}"), "then joins the rotation", seen)

        # A restart: the saved registry's members back in rotation at once.
        time.sleep(1.5)   # (the registry saved after B2 joined)
        stop(p)
        p = start(log)
        seen = hammer(1.5)
        check(only_200(seen) and seen.get(f"200 {B1}") and seen.get(f"200 {B2}"),
              "after a restart, the members restored from the registry serve at once", seen)

        # An upgrade (the same binary): no answer but theirs while the workers are replaced.
        result = {}

        def during():
            result["seen"] = hammer(3.0)
        t = threading.Thread(target=during)
        t.start()
        time.sleep(0.3)
        r = subprocess.run([BIN, "upgrade", "-c", CFG], capture_output=True, text=True, timeout=30)
        t.join()
        check(r.returncode == 0, "the upgrade is taken", r.stdout + r.stderr)
        check(only_200(result.get("seen", {})), "through an upgrade, the members serve throughout", result.get("seen"))

        text = open(os.path.join(TMP, "limer.log")).read()
        check("restored" in text, "the log says which members were restored", "")
        check("AddressSanitizer" not in text and "runtime error" not in text, "no sanitizer reports")
    finally:
        stop(p)

    print(f"\nkeep tests: passed {PASS}, failed {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
