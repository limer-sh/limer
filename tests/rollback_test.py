#!/usr/bin/env python3
"""
Functional test for auto_rollback: a reload whose new config makes responses
fail is reverted to the previous configuration automatically.

Runs traffic continuously while it (1) reloads to another healthy backend,
which must be committed, then (2) reloads to a dead backend, which must be
rolled back to the healthy one.

    python3 tests/rollback_test.py        # from the repository root
"""
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "rollback")
os.makedirs(TMP, exist_ok=True)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
SITE, GOOD, NEXT, DEAD = 9880, 9881, 9882, 9889
CFG = os.path.abspath(os.path.join(TMP, "Limerfile"))
PIDFILE = os.path.abspath(os.path.join(TMP, "limer.pid"))
LOG = os.path.abspath(os.path.join(TMP, "limer.log"))
PROCS = []
PASS = FAIL = 0
samples = []          # (time, status, body)
stop_traffic = threading.Event()


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


def write_cfg(upstream_port):
    with open(CFG, "w") as f:
        f.write(f"""{{
    admin off
    pidfile {PIDFILE}
    log_level info
    auto_rollback {{
        error_rate 30%
        window 6s
        min_requests 10
    }}
}}
127.0.0.1:{SITE} {{
    reverse_proxy 127.0.0.1:{upstream_port}
}}
""")


def traffic():
    while not stop_traffic.is_set():
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{SITE}/", timeout=2) as r:
                samples.append((time.time(), r.status, r.read().decode().strip()))
        except urllib.error.HTTPError as e:
            samples.append((time.time(), e.code, ""))
        except Exception:
            samples.append((time.time(), None, ""))
        time.sleep(0.005)


def reload():
    subprocess.run([BIN, "reload", "-c", CFG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def window(t0, t1):
    return [s for s in samples if t0 <= s[0] < t1]


def main():
    for port, name in ((GOOD, "good"), (NEXT, "next")):
        PROCS.append(subprocess.Popen([sys.executable, "tests/backend.py", str(port), name],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        wait_port(port)
    write_cfg(GOOD)
    log = open(LOG, "w")
    PROCS.append(subprocess.Popen([BIN, "run", "-c", CFG], stdout=subprocess.DEVNULL, stderr=log))
    t = threading.Thread(target=traffic, daemon=True)
    try:
        if not wait_port(SITE):
            raise SystemExit("limer did not come up")
        time.sleep(0.5)
        t.start()
        time.sleep(1)

        # 1) a healthy change is committed after the probation window
        write_cfg(NEXT)
        t1 = time.time()
        reload()
        time.sleep(8)
        tail = window(time.time() - 1.5, time.time())
        if tail and all(s[1] == 200 and s[2] == "hello from next" for s in tail):
            ok("a healthy reload is applied and kept")
        else:
            bad("healthy reload kept", f"tail={tail[-3:]}")
        logtext = open(LOG).read()
        (ok if "committed" in logtext else bad)("the healthy config is committed after probation")
        (ok if "auto-rollback" not in logtext else bad)("no rollback for a healthy config")

        # 2) a change that breaks responses is rolled back automatically
        write_cfg(DEAD)
        t2 = time.time()
        reload()
        time.sleep(5)
        after = window(t2, time.time())
        saw_errors = any(s[1] is not None and s[1] >= 500 for s in after)
        tail = window(time.time() - 1.0, time.time())
        logtext = open(LOG).read()
        (ok if saw_errors else bad)("the broken config did produce 5xx", f"{len(after)} samples")
        (ok if "auto-rollback" in logtext else bad)("the master detected it and rolled back")
        if tail and all(s[1] == 200 and s[2] == "hello from next" for s in tail):
            ok("traffic is served by the previous config again")
        else:
            bad("served by previous config after rollback", f"tail={tail[-3:]}")
        bad_window = [s for s in after if s[1] is None or s[1] >= 500]
        if bad_window:
            span = bad_window[-1][0] - bad_window[0][0]
            print(f"         (errors lasted {span:.1f}s, {len(bad_window)} failed requests)")
    finally:
        stop_traffic.set()
        if t.is_alive():
            t.join(timeout=3)
        for p in reversed(PROCS):
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                p.kill()

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
