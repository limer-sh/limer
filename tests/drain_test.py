#!/usr/bin/env python3
"""
Functional test for the admin self-drain endpoints (POST /drain, /undrain).

A backend signals limer, during graceful shutdown, to stop sending it new
requests. The endpoint drains the upstream(s) at the caller's own address, so
calling it from 127.0.0.1 drains the 127.0.0.1 upstream.

    python3 tests/drain_test.py        # from the repository root
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "drain")
os.makedirs(TMP, exist_ok=True)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
SITE, BACKEND, ADMIN = 9850, 9851, 9859
PROCS = []
PASS = FAIL = 0


def ok(n, d=""):
    global PASS
    PASS += 1
    print(f"  ok   - {n}")


def bad(n, d=""):
    global FAIL
    FAIL += 1
    print(f"  FAIL - {n}")
    if d:
        print(f"         {d}")


def wait_port(port, tries=100):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def status(url, method="GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:  # connection error
        return None, str(e)


def main():
    storage = os.path.abspath(os.path.join(TMP, "storage"))
    os.makedirs(storage, exist_ok=True)
    try:
        os.unlink(os.path.join(storage, "overrides.conf"))
    except OSError:
        pass
    PROCS.append(subprocess.Popen([sys.executable, "tests/backend.py", str(BACKEND), "app"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    wait_port(BACKEND)
    cfg = f"""{{
    admin 127.0.0.1:{ADMIN}
    storage {storage}
    log_level error
}}
127.0.0.1:{SITE} {{
    reverse_proxy 127.0.0.1:{BACKEND}
}}
"""
    path = os.path.join(TMP, "Limerfile")
    with open(path, "w") as f:
        f.write(cfg)
    log = open(os.path.join(TMP, "limer.log"), "w")
    PROCS.append(subprocess.Popen([BIN, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=log))
    try:
        if not wait_port(SITE) or not wait_port(ADMIN):
            raise SystemExit("limer did not come up")
        site = f"http://127.0.0.1:{SITE}/"
        admin = f"http://127.0.0.1:{ADMIN}"

        s, _ = status(site)
        (ok if s == 200 else bad)("serves through the backend before drain", f"status={s}")

        s, _ = status(f"{admin}/drain", "GET")
        (ok if s == 405 else bad)("drain requires POST", f"status={s}")

        s, body = status(f"{admin}/drain", "POST")
        try:
            j = json.loads(body)
        except ValueError:
            j = {}
        if s == 200 and j.get("drained") is True and f"127.0.0.1:{BACKEND}" in j.get("upstreams", []):
            ok("POST /drain drains the caller's own upstream")
        else:
            bad("POST /drain drains the caller's upstream", f"status={s} body={body[:120]}")

        time.sleep(0.8)  # the drain propagates through a reload
        s, _ = status(site)
        (ok if s == 503 else bad)("drained upstream receives no new requests", f"status={s}")

        s, body = status(f"{admin}/undrain", "POST")
        (ok if s == 200 and '"drained":false' in body else bad)("POST /undrain restores it", f"status={s}")

        time.sleep(0.8)
        s, _ = status(site)
        (ok if s == 200 else bad)("serves again after undrain", f"status={s}")
    finally:
        for p in PROCS:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                p.kill()

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
