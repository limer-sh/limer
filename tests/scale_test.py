#!/usr/bin/env python3
"""
Functional test for the scale_up load-spike hook.

Starts a Limer instance whose scale_up block runs a small script when the
request rate crosses a low threshold, hammers it, and checks the hook ran once
(cooldown holds off repeats) with the trigger context in the environment.

    python3 tests/scale_test.py        # from the repository root
"""
import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "scale")
os.makedirs(TMP, exist_ok=True)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
PORT = 9671
HOOK_OUT = os.path.abspath(os.path.join(TMP, "fired.log"))
PASS = FAIL = 0


def ok(n):
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


def hammer(seconds):
    import urllib.request
    end = time.time() + seconds
    n = 0
    while time.time() < end:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=1).read()
            n += 1
        except Exception:
            pass
    return n


def main():
    try:
        os.unlink(HOOK_OUT)
    except OSError:
        pass
    cfg = f"""{{
    admin off
    log_level error
    scale_up {{
        requests 100r/s
        sustain 0s
        cooldown 10s
        exec "echo $LIMER_SCALE_REASON $LIMER_SCALE_CONNS >> {HOOK_OUT}"
    }}
}}
127.0.0.1:{PORT} {{
    respond "ok"
}}
"""
    path = os.path.join(TMP, "Limerfile")
    with open(path, "w") as f:
        f.write(cfg)
    log = open(os.path.join(TMP, "limer.log"), "w")
    p = subprocess.Popen([BIN, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=log)
    try:
        if not wait_port(PORT):
            raise SystemExit("limer did not come up")
        sent = hammer(2.5)   # well above 100 r/s
        time.sleep(1.0)      # let the hook (double-forked) write

        lines = []
        try:
            with open(HOOK_OUT) as f:
                lines = [ln.strip() for ln in f if ln.strip()]
        except OSError:
            pass

        if lines:
            ok(f"hook ran on a {sent/2.5:.0f} req/s spike")
        else:
            bad("hook ran on spike", "hook output file is empty/missing")

        if lines and lines[0].split()[0] == "requests":
            ok("hook received the trigger reason (requests)")
        else:
            bad("hook trigger context", f"first line: {lines[0] if lines else '(none)'}")

        if len(lines) == 1:
            ok("cooldown held the hook to a single run during the spike")
        else:
            bad("cooldown limits repeats", f"hook ran {len(lines)} times")
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
