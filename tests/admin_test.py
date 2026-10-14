#!/usr/bin/env python3
"""
Functional test for admin API protection: the shared secret, the webhook rate
limit, bans for wrong secrets and floods, and POST /scale_up.

Callers are told apart by source address on loopback: 127.0.0.1 behaves,
127.0.0.2 guesses secrets, 127.0.0.3 floods the webhooks.

    python3 tests/admin_test.py        # from the repository root
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "admin")
os.makedirs(TMP, exist_ok=True)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
ADMIN, SITE, BACKEND, ADMIN2 = 9951, 9952, 9953, 9954
SECRET = "s3cret-for-tests-0123456789abcdef"
HOOK_OUT = os.path.abspath(os.path.join(TMP, "hook.out"))
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
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def wait_tcp(port, tries=200):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def call(method, path, src="127.0.0.1", secret=None, port=ADMIN):
    """One admin request from a chosen source address; returns (status, headers, json-or-text)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5, source_address=(src, 0))
    hdrs = {"Authorization": f"Bearer {secret}"} if secret else {}
    conn.request(method, path, headers=hdrs)
    r = conn.getresponse()
    body = r.read().decode()
    conn.close()
    try:
        body = json.loads(body)
    except ValueError:
        pass
    return r.status, {k.lower(): v for k, v in r.getheaders()}, body


def can_bind(ip):
    """Linux answers on all of 127.0.0.0/8; macOS only on 127.0.0.1 unless aliases are added."""
    try:
        s = socket.socket()
        s.bind((ip, 0))
        s.close()
        return True
    except OSError:
        return False


def hook_lines(want, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        try:
            lines = open(HOOK_OUT).read().split("\n")
            lines = [l for l in lines if l]
            if len(lines) >= want:
                return lines
        except OSError:
            pass
        time.sleep(0.05)
    try:
        return [l for l in open(HOOK_OUT).read().split("\n") if l]
    except OSError:
        return []


def validate(text):
    path = os.path.join(TMP, "check.Limerfile")
    with open(path, "w") as f:
        f.write(text)
    p = subprocess.run([BIN, "validate", "-c", path], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def config_tests():
    print("config")
    rc, out = validate("{\n    admin 127.0.0.1:9959 {\n        secret short\n    }\n}\n:9958 {\n    respond ok\n}\n")
    check(rc != 0 and "at least 16 characters" in out, "a short secret is rejected", out.strip()[-120:])
    rc, out = validate("{\n    admin 127.0.0.1:9959 {\n        sekret x\n    }\n}\n:9958 {\n    respond ok\n}\n")
    check(rc != 0 and "unknown admin option" in out, "an unknown admin option is rejected", out.strip()[-120:])
    rc, out = validate("{\n    scale_up {\n        exec true\n    }\n}\n:9958 {\n    respond ok\n}\n")
    check(rc != 0 and "POST /scale_up" in out, "scale_up with no threshold needs the admin API", out.strip()[-120:])
    rc, out = validate("{\n    admin 0.0.0.0:9959\n}\n:9958 {\n    respond ok\n}\n")
    check(rc == 0 and "has no secret" in out, "an admin API open beyond loopback without a secret is warned about",
          out.strip()[-160:])
    rc, out = validate("{\n    admin 127.0.0.1:9959\n}\n:9958 {\n    respond ok\n}\n")
    check(rc == 0 and "has no secret" not in out, "a loopback admin API without a secret is not warned about")


def caller_tests():
    """Bans and their expiry, with callers told apart by source address."""
    print("bans for wrong secrets")
    for i in range(3):
        s, _, _ = call("GET", "/upstreams", src="127.0.0.2", secret=f"guess-{i}-0123456789abcdef")
    check(s == 401, "three wrong guesses are each refused", f"{s}")
    s, h, b = call("GET", "/upstreams", src="127.0.0.2", secret=SECRET)
    check(s == 403 and int(h.get("retry-after", "0")) >= 1, "then the guesser is banned, even with the right secret",
          f"{s} {h.get('retry-after')} {b}")
    s, _, _ = call("GET", "/upstreams", secret=SECRET)
    check(s == 200, "other callers are unaffected", f"{s}")

    print("bans for floods")
    codes = [call("POST", "/drain", src="127.0.0.3", secret=SECRET)[0] for _ in range(6)]
    check(codes[0] != 429 and codes[1] != 429, "calls within the burst go through", f"{codes}")
    check(codes[2:5] == [429, 429, 429], "calls beyond the rate get 429", f"{codes}")
    check(codes[5] == 403, "repeated floods earn a ban", f"{codes}")

    print("ban expiry")
    time.sleep(3.3)
    s, _, _ = call("GET", "/upstreams", src="127.0.0.2", secret=SECRET)
    check(s == 200, "the ban lifts after its duration", f"{s}")


def shared_cooldown_test():
    """Two workers, two simultaneous webhook calls: the hook runs once."""
    print("cooldown shared by every worker")
    out = os.path.abspath(os.path.join(TMP, "hook2.out"))
    try:
        os.unlink(out)
    except OSError:
        pass
    cfg = os.path.join(TMP, "Limerfile2")
    with open(cfg, "w") as f:
        f.write(f"""{{
    log_level warn
    workers 2
    admin 127.0.0.1:{ADMIN2} {{
        secret {SECRET}
        rate off
    }}
    scale_up {{
        cooldown 30s
        exec "echo ran >> {out}"
    }}
}}
127.0.0.1:{SITE} {{
    respond ok
}}
""")
    log = open(os.path.join(TMP, "limer2.log"), "w")
    p = subprocess.Popen([BIN, "run", "-c", cfg], stdout=subprocess.DEVNULL, stderr=log)
    try:
        if not wait_tcp(ADMIN2):
            raise SystemExit("second limer did not come up")
        time.sleep(0.5)                      # both workers listening
        codes = []
        for _ in range(8):                   # spread over both workers by the kernel
            codes.append(call("POST", "/scale_up", secret=SECRET, port=ADMIN2)[0])
        time.sleep(0.5)
        try:
            ran = [l for l in open(out).read().split("\n") if l]
        except OSError:
            ran = []
        check(codes.count(202) == 1 and codes.count(429) == 7, "eight calls across two workers: one run, seven refusals",
              f"{codes}")
        check(len(ran) == 1, "the hook ran once", f"{ran}")
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def main():
    config_tests()

    srv = ThreadingHTTPServer(("127.0.0.1", BACKEND), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        os.unlink(HOOK_OUT)
    except OSError:
        pass
    cfg = os.path.join(TMP, "Limerfile")
    with open(cfg, "w") as f:
        f.write(f"""{{
    log_level warn
    workers 1
    admin 127.0.0.1:{ADMIN} {{
        secret {SECRET}
        rate 30/m
        burst 2
        max_failures 3
        ban 3s
    }}
    scale_up {{
        cooldown 2s
        exec "echo $LIMER_SCALE_REASON $LIMER_SCALE_CALLER >> {HOOK_OUT}"
    }}
}}
127.0.0.1:{SITE} {{
    reverse_proxy 127.0.0.1:{BACKEND}
}}
""")
    log = open(os.path.join(TMP, "limer.log"), "w")
    p = subprocess.Popen([BIN, "run", "-c", cfg], stdout=subprocess.DEVNULL, stderr=log)
    try:
        if not (wait_tcp(ADMIN) and wait_tcp(SITE)):
            raise SystemExit("limer did not come up")
        print("secret")
        s, _, _ = call("GET", "/health")
        check(s == 200, "/health stays open without the secret", f"{s}")
        s, h, _ = call("GET", "/upstreams")
        check(s == 401 and h.get("www-authenticate", "").startswith("Bearer"),
              "no secret: 401 with a Bearer challenge", f"{s} {h.get('www-authenticate')}")
        s, _, _ = call("GET", "/config", secret="wrong-" + SECRET)
        check(s == 401, "wrong secret: 401", f"{s}")
        s, _, b = call("GET", "/upstreams", secret=SECRET)
        check(s == 200 and isinstance(b, dict), "right secret: 200", f"{s}")

        print("scale_up webhook")
        s, _, b = call("POST", "/scale_up", secret=SECRET)
        check(s == 202, "POST /scale_up runs the hook: 202", f"{s} {b}")
        lines = hook_lines(1)
        check(lines[:1] == ["webhook 127.0.0.1"], "the hook sees LIMER_SCALE_REASON=webhook and the caller", f"{lines}")
        s, h, b = call("POST", "/scale_up", secret=SECRET)
        check(s == 429 and int(h.get("retry-after", "0")) >= 1 and isinstance(b, dict) and b.get("status") == "cooling down",
              "a second call inside the cooldown is refused with Retry-After", f"{s} {h.get('retry-after')} {b}")
        time.sleep(0.5)
        check(len(hook_lines(2, timeout=0.5)) == 1, "...and the hook did not run again")
        aliases = all(can_bind(f"127.0.0.{i}") for i in (2, 3, 5))
        if not aliases:
            print("  skip - the per-caller checks need 127.0.0.2, .3 and .5 on the loopback")
            print("         (macOS: sudo ifconfig lo0 alias 127.0.0.2 up; likewise .3 and .5)")
            time.sleep(3.5)   # what caller_tests() would take: refills this caller's webhook bucket
        else:
            s, _, _ = call("GET", "/scale_up", src="127.0.0.5", secret=SECRET)
            check(s == 405, "GET /scale_up: 405", f"{s}")
            caller_tests()

        print("self-drain with the secret")
        s, _, b = call("POST", "/drain", secret=SECRET)
        check(s == 200 and isinstance(b, dict) and b.get("drained") is True, "POST /drain with the secret drains the caller",
              f"{s} {b}")
        s, _, b = call("POST", "/undrain", secret=SECRET)
        check(s == 200 and isinstance(b, dict) and b.get("drained") is False, "POST /undrain restores it", f"{s} {b}")

        text = open(os.path.join(TMP, "limer.log")).read()
        if aliases:
            check("banned 127.0.0.2" in text and "banned 127.0.0.3" in text, "bans are logged")
        check("AddressSanitizer" not in text and "runtime error" not in text, "no sanitizer reports")
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()

    shared_cooldown_test()
    print(f"\nadmin tests: passed {PASS}, failed {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
