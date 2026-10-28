#!/usr/bin/env python3
"""
Functional test for reloads that answer, and for checks that create nothing.

  - `limer validate` checks access log files without creating them (run as
    root, it used to create them root-owned, and the server could not write
    them), and still refuses one the server could not write;
  - `limer reload` waits for the master's answer: it exits 0 when the workers
    reload, 1 with the reason when the master refuses the configuration, and 1
    when nothing answers;
  - the master keeps answering while the certificate manager is in its failure
    backoff: a reload restarts the manager, which used to inherit the master's
    blocked signals, so the next reload hung the master for good
    (BUGREPORT1.md). The CA here refuses connections, so every order fails.

    python3 tests/reload_test.py        # from the repository root
"""
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "reload")
shutil.rmtree(TMP, ignore_errors=True)
os.makedirs(TMP)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
HTTP, HTTPS, CLOSED = 9960, 9961, 9962
CFG = os.path.join(TMP, "Limerfile")
PIDFILE = os.path.join(TMP, "limer.pid")
LOG = os.path.join(TMP, "limer.log")
ACCESS = os.path.join(TMP, "access.log")
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


def limer(*args, timeout=30):
    t = time.monotonic()
    r = subprocess.run([BIN, *args], capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr, time.monotonic() - t


def write_config(extra=""):
    with open(CFG, "w") as f:
        f.write(f"""{{
    http_port {HTTP}
    https_port {HTTPS}
    storage {TMP}/storage
    pidfile {os.path.abspath(PIDFILE)}
    acme_ca https://127.0.0.1:{CLOSED}/dir
    email admin@reload.example.com
    log_level info
}}

http://127.0.0.1:{HTTP} {{
    log {{
        output file {os.path.abspath(ACCESS)}
    }}
    respond "ok"
}}

reload.example.com {{
    respond "tls"
}}
{extra}""")


def log_text():
    with open(LOG) as f:
        return f.read()


def wait_for(pred, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.1)
    return pred()


for port in (HTTP, HTTPS):
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", port)) == 0:
            print(f"port {port} is already in use by another program; free it and re-run")
            sys.exit(1)

print("# validate creates no log file")
write_config()
code, out, _ = limer("validate", "-c", CFG)
check(code == 0, "validate accepts the config", out)
check(not os.path.exists(ACCESS), "validate did not create the access log")

with open(ACCESS, "w"):
    pass
if os.geteuid() == 0:
    # root writes anything: the case is the incident's, a file of root's in a directory of the server's user
    os.chown(TMP, 65534, -1)
    code, out, _ = limer("validate", "-c", CFG)
    os.chown(TMP, 0, -1)
    check(code == 1 and "belongs to root" in out, "validate refuses a root-owned access log in another user's directory", out)
else:
    os.chmod(ACCESS, 0o444)
    code, out, _ = limer("validate", "-c", CFG)
    check(code == 1 and "cannot write log file" in out, "validate refuses an access log it cannot write", out)
os.unlink(ACCESS)

print("# a running server")
proc = subprocess.Popen([BIN, "run", "-c", CFG], stdout=subprocess.DEVNULL, stderr=open(LOG, "w"))
try:
    check(wait_for(lambda: os.path.exists(PIDFILE) and "will retry" in log_text(), 15),
          "the certificate manager fails against the closed CA and backs off", log_text()[-400:])
    urllib.request.urlopen(f"http://127.0.0.1:{HTTP}/", timeout=5).read()
    check(wait_for(lambda: os.path.exists(ACCESS) and os.path.getsize(ACCESS) > 0, 5),
          "the server itself creates and writes the access log")

    print("# reload answers, also during the certificate manager's backoff")
    for n in (1, 2, 3):
        code, out, took = limer("reload", "-c", CFG)
        check(code == 0 and "reloaded (pid" in out and took < 5,
              f"reload {n} is answered: exit {code} in {took:.1f}s", out)
    started = len(re.findall(r"certificate manager started", log_text()))
    check(started >= 4, f"each reload restarted the certificate manager ({started} starts)")

    print("# reloads back to back: the next one stops a manager forked a moment before")
    master = int(open(PIDFILE).read())
    for _ in range(4):
        os.kill(master, signal.SIGHUP)
        time.sleep(0.002)
    code, out, took = limer("reload", "-c", CFG)
    check(code == 0 and took < 3, f"a reload after them is answered: exit {code} in {took:.1f}s", out)
    check("did not stop on SIGTERM" not in log_text(), "the certificate manager stopped on SIGTERM every time",
          "\n".join(l for l in log_text().splitlines() if "did not stop" in l))

    print("# a configuration the master refuses")
    with open(CFG, "a") as f:
        f.write("\nbroken.example.com {\n    reverse_proxy\n}\n")
    code, out, took = limer("reload", "-p", PIDFILE)   # -p: the command itself reads no config
    check(code == 1 and "configuration invalid" in out, "reload reports the master's refusal", out)
    write_config()
    code, out, _ = limer("reload", "-c", CFG)
    check(code == 0, "a reload after that one is answered", out)

    print("# stop is prompt")
    t = time.monotonic()
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        pass
    check(proc.poll() is not None and time.monotonic() - t < 6,
          f"the master stopped in {time.monotonic() - t:.1f}s")
finally:
    if proc.poll() is None:
        proc.kill()
        proc.wait()

print("# a pid that never answers")
silent = subprocess.Popen([sys.executable, "-c",
                           "import signal, time; signal.signal(signal.SIGHUP, signal.SIG_IGN); time.sleep(60)"])
try:
    time.sleep(0.3)
    with open(PIDFILE, "w") as f:
        f.write(f"{silent.pid}\n")
    code, out, took = limer("reload", "-p", PIDFILE)
    check(code == 1 and "did not answer the reload" in out, f"reload gives up after {took:.0f}s and says so", out)
finally:
    silent.kill()
    silent.wait()

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
