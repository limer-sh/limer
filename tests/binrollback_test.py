#!/usr/bin/env python3
"""
Functional test for binary auto-rollback on `limer upgrade`.

Builds a deliberately broken variant of limer (it passes `validate` but answers
every request with 500), then, under continuous traffic:

  1. upgrades to a good binary, which must be committed after the probation;
  2. upgrades to the broken binary, which must be rolled back automatically.

The master's pid must never change. Building the variant takes a while on a
small machine.

    python3 tests/binrollback_test.py        # from the repository root
"""
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.abspath(os.path.join("tests", "tmp", "binrollback"))
os.makedirs(TMP, exist_ok=True)

GOOD_BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./limer")
LIVE = os.path.join(TMP, "limer")          # the path the master runs from; upgrades replace it
CFG = os.path.join(TMP, "Limerfile")
PIDFILE = os.path.join(TMP, "limer.pid")
LOG = os.path.join(TMP, "limer.log")
STORAGE = os.path.join(TMP, "storage")
SITE = 9890
PASS = FAIL = 0
samples = []
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


def wait_port(port, tries=200):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def build_broken():
    out = os.path.join(TMP, "broken")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    shutil.copytree("src", os.path.join(out, "src"))
    shutil.copy("Makefile", out)
    path = os.path.join(out, "src", "proxy.c")
    src = open(path).read()
    marker = "static void conn_dispatch(conn_t *c)\n{\n    http_req_t *r = &c->req;\n    g_stats.requests++;\n"
    if marker not in src:
        raise SystemExit("cannot find conn_dispatch to break")
    src = src.replace(marker, marker + "    conn_send_error(c, 500, \"broken build\", 0);\n    return;\n")
    open(path, "w").write(src)
    subprocess.run(["make", "-s", "-C", out], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return os.path.join(out, "limer")


def install(src):
    """Replace the live binary the way `make install` does: a new file, renamed into place."""
    tmp = LIVE + ".new"
    shutil.copy(src, tmp)
    os.chmod(tmp, 0o755)
    os.replace(tmp, LIVE)


def traffic():
    while not stop_traffic.is_set():
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{SITE}/", timeout=2) as r:
                samples.append((time.time(), r.status))
        except urllib.error.HTTPError as e:
            samples.append((time.time(), e.code))
        except Exception:
            samples.append((time.time(), None))
        time.sleep(0.004)


def since(t0):
    return [s for s in samples if s[0] >= t0]


def master_pid():
    try:
        return int(open(PIDFILE).read().strip())
    except (OSError, ValueError):
        return None


def upgrade():
    subprocess.run([LIVE, "upgrade", "-c", CFG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def upgrade_after_reload():
    """A reload restarts the certificate manager from inside the master's loop, where the master
    blocks its signals. The next upgrade stops that manager first: it must not wait on it forever."""
    print("upgrade after a reload restarted the certificate manager")
    d = os.path.join(TMP, "acme-upgrade")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    live = os.path.join(d, "limer")
    shutil.copy2(GOOD_BIN, live)
    cfg, pidf, logf = os.path.join(d, "Limerfile"), os.path.join(d, "limer.pid"), os.path.join(d, "limer.log")
    with open(cfg, "w") as f:
        # a public name starts the certificate manager; its CA is a closed local port, so nothing leaves the machine
        f.write(f"""{{
    log_level info
    admin off
    storage {d}/storage
    pidfile {pidf}
    acme_ca https://127.0.0.1:1/directory
    http_port 9893
    https_port 9894
}}
upgrade.example.com {{
    respond "public"
}}
127.0.0.1:9895 {{
    respond "local"
}}
""")
    log = open(logf, "w")
    p = subprocess.Popen([live, "run", "-c", cfg], stdout=subprocess.DEVNULL, stderr=log)

    def log_has(text, count=1, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            if open(logf).read().count(text) >= count:
                return True
            time.sleep(0.1)
        return False

    try:
        if not wait_port(9895) or not log_has("certificate manager started"):
            bad("instance with a certificate manager starts", open(logf).read()[-300:])
            return
        subprocess.run([live, "reload", "-c", cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (ok if log_has("certificate manager started", 2) else bad)("a reload restarts the certificate manager")
        subprocess.run([live, "upgrade", "-c", cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (ok if log_has("re-executing into the new binary", timeout=8) else bad)(
            "the upgrade goes through within seconds", open(logf).read()[-400:])
        try:
            body = urllib.request.urlopen("http://127.0.0.1:9895/", timeout=5).read().decode()
        except OSError as e:
            body = str(e)
        (ok if body == "local" else bad)("the site answers after the upgrade", body)
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def main():
    print("building a broken variant of limer...")
    broken = build_broken()
    shutil.rmtree(STORAGE, ignore_errors=True)
    for f in os.listdir(TMP):
        if f.startswith("limer.rejected-"):
            os.unlink(os.path.join(TMP, f))
    install(GOOD_BIN)
    with open(CFG, "w") as f:
        f.write(f"""{{
    admin off
    pidfile {PIDFILE}
    storage {STORAGE}
    log_level info
    workers 2
    auto_rollback {{
        error_rate 30%
        window 5s
        min_requests 10
    }}
}}
127.0.0.1:{SITE} {{
    respond "ok"
}}
""")
    log = open(LOG, "w")
    p = subprocess.Popen([LIVE, "run", "-c", CFG], stdout=subprocess.DEVNULL, stderr=log)
    t = threading.Thread(target=traffic, daemon=True)
    try:
        if not wait_port(SITE):
            raise SystemExit("limer did not come up")
        time.sleep(0.5)
        pid0 = master_pid()
        t.start()
        time.sleep(1)

        # 1) a good binary is committed after its probation
        install(GOOD_BIN)
        t1 = time.time()
        upgrade()
        time.sleep(8)
        text = open(LOG).read()
        (ok if "on probation" in text else bad)("the new binary runs on probation first")
        (ok if "new binary committed" in text else bad)("a healthy binary is committed")
        errs = [s for s in since(t1) if s[1] != 200]
        (ok if not errs else bad)("no failed requests during a healthy upgrade", f"{len(errs)} failed")

        # 2) a broken binary is rolled back automatically
        install(broken)
        t2 = time.time()
        upgrade()
        time.sleep(7)
        text = open(LOG).read()
        after = since(t2)
        failed = [s for s in after if s[1] != 200]
        (ok if failed else bad)("the broken binary did serve 500s while on probation")
        (ok if "upgrade rollback" in text else bad)("the master rolled the binary back")
        tail = since(time.time() - 1.0)
        if tail and all(s[1] == 200 for s in tail):
            ok("traffic is all 200 again on the previous binary")
        else:
            bad("served by the previous binary after rollback", f"tail={tail[-5:]}")
        if failed:
            share = len(failed) / max(1, len(after))
            print(f"         ({len(failed)} of {len(after)} requests failed during the canary, {share:.0%})")
        (ok if master_pid() == pid0 and pid0 else bad)("the master pid never changed", f"{pid0} -> {master_pid()}")

        # the broken binary must not come back on a restart
        same = open(LIVE, "rb").read() == open(GOOD_BIN, "rb").read()
        (ok if same else bad)("the previous binary is restored at the installed path")
        rejected = [f for f in os.listdir(TMP) if f.startswith("limer.rejected-")]
        kept = rejected and open(os.path.join(TMP, rejected[0]), "rb").read() == open(broken, "rb").read()
        (ok if kept else bad)("the broken binary is kept as limer.rejected-<time>", str(rejected))
    finally:
        stop_traffic.set()
        if t.is_alive():
            t.join(timeout=3)
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()

    upgrade_after_reload()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
