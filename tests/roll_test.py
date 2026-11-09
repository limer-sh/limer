#!/usr/bin/env python3
"""
Functional test for access log files that roll (`output file <path> { roll_... }`), as Caddy's:

  - `limer validate` takes the roll_ options, refuses a bad size, an unknown option, and the
    options on a log that is no file;
  - past roll_size, the file is renamed to <name>-<UTC time>.<ext>, gzipped on a thread, and a
    new one opened; four workers write one file, roll it once each time, and lose no line;
  - roll_keep keeps that many rolled files, roll_keep_for removes older ones, roll_uncompressed
    leaves them plain, roll_local_time names them in local time;
  - a file moved away from under the server (logrotate without copytruncate) is followed: the
    path is opened again within a second;
  - with roll_disabled the file grows and nothing is renamed.

    python3 tests/roll_test.py        # from the repository root
"""
import calendar
import glob
import gzip
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.abspath(os.path.join("tests", "tmp", "roll"))
shutil.rmtree(TMP, ignore_errors=True)
os.makedirs(TMP)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
PORT = 9971
CFG = os.path.join(TMP, "Limerfile")
LOG = os.path.join(TMP, "limer.log")
PASS = FAIL = 0
ROLLED = re.compile(r"^access-(\d{4})-(\d\d)-(\d\d)T(\d\d)-(\d\d)-(\d\d)\.(\d{3})(-\d+)?\.log(\.gz)?$")


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


def write_config(log_dir, options, workers=4):
    os.makedirs(log_dir, exist_ok=True)
    with open(CFG, "w") as f:
        f.write(f"""{{
    http_port {PORT}
    auto_https off
    workers {workers}
    log_level info
}}

http://127.0.0.1:{PORT} {{
    log {{
        output file {log_dir}/access.log {{
{options}
        }}
        format json
    }}
    respond "ok"
}}
""")


def validate():
    r = subprocess.run([BIN, "validate", "-c", CFG], capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


def start(env=None):
    p = subprocess.Popen([BIN, "run", "-c", CFG], stdout=subprocess.DEVNULL, stderr=open(LOG, "w"),
                         env={**os.environ, **(env or {})})
    for _ in range(100):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", PORT)) == 0:
                return p
        time.sleep(0.05)
    p.kill()
    raise SystemExit("limer did not start:\n" + open(LOG).read())


def stop(p):
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def get(n, tag):
    for i in range(n):
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/{tag}/{i}", timeout=5).read()


def rounds(count, per, tag):
    """`count` rounds of `per` requests, a little over a second apart: each worker looks at
    its file at most once a second."""
    for r in range(count):
        get(per, f"{tag}{r}")
        time.sleep(1.2)


def rolled(log_dir):
    return sorted(f for f in os.listdir(log_dir) if ROLLED.match(f))


def lines(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as f:
        return [l for l in f.read().splitlines() if l.strip()]


def wait_for(pred, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.1)
    return pred()


with socket.socket() as s:
    if s.connect_ex(("127.0.0.1", PORT)) == 0:
        print(f"port {PORT} is already in use by another program; free it and re-run")
        sys.exit(1)

print("# validate")
d = os.path.join(TMP, "v")
write_config(d, "            roll_size 4KiB\n            roll_keep 3\n            roll_keep_for 90d\n            roll_uncompressed\n            roll_local_time")
code, out = validate()
check(code == 0, "validate takes the roll_ options", out)
write_config(d, "            roll_size lots")
code, out = validate()
check(code == 1 and "roll_size must be a size such as 100MiB, got 'lots'" in out, "a size that is none is refused", out)
write_config(d, "            roll_size 0")
code, out = validate()
check(code == 1 and "roll_size must be a size" in out, "a size of 0 is refused", out)
write_config(d, "            roll_every 1h")
code, out = validate()
check(code == 1 and "unknown option 'roll_every' of 'output file'" in out, "an unknown option is refused, naming those there are", out)
write_config(d, "            roll_keep -1")
code, out = validate()
check(code == 1 and "invalid number" in out, "a negative roll_keep is refused", out)
with open(CFG, "w") as f:
    f.write(f"""{{
    http_port {PORT}
    auto_https off
}}
http://127.0.0.1:{PORT} {{
    log {{
        output stdout {{
            roll_size 1MiB
        }}
    }}
    respond "ok"
}}
""")
code, out = validate()
check(code == 1 and "the roll_ options are for 'output file'" in out, "the options on stdout are refused", out)

print("# four workers roll one file, gzip what they rolled, and keep three")
d = os.path.join(TMP, "keep")
write_config(d, "            roll_size 4KiB\n            roll_keep 3")
p = start()
try:
    rounds(8, 40, "k")
    check(wait_for(lambda: not glob.glob(f"{d}/*.gz.tmp") and all(f.endswith(".gz") for f in rolled(d)), 10),
          "every rolled file is gzipped, none left half written", os.listdir(d))
    names = rolled(d)
    check(len(names) == 3, f"three rolled files are kept: {len(names)}", names)
    check(all(f.endswith(".log.gz") for f in names), "rolled files are named <name>-<UTC time>.log.gz", names)
    ok = True
    for f in names:
        for l in lines(os.path.join(d, f)):
            json.loads(l.split(" ", 1)[1])
    check(ok, "each rolled file decompresses to whole access lines")
    size = os.path.getsize(os.path.join(d, "access.log"))
    check(size < 4096 * 4, f"the open file stays near roll_size: {size} bytes")
    text = open(LOG).read()
    check("rolled to" in text and "cannot" not in text, "the log says each roll, and no failure", text[-400:])
finally:
    stop(p)

print("# no line is lost")
d = os.path.join(TMP, "all")
write_config(d, "            roll_size 4KiB\n            roll_keep 0\n            roll_keep_for 0")
p = start()
try:
    rounds(6, 40, "a")
    get(5, "last")
    time.sleep(0.5)
    check(wait_for(lambda: not glob.glob(f"{d}/*.gz.tmp") and all(f.endswith(".gz") for f in rolled(d)), 10), "all compressed")
    every = lines(os.path.join(d, "access.log"))
    for f in rolled(d):
        every += lines(os.path.join(d, f))
    uris = [json.loads(l.split(" ", 1)[1])["uri"] for l in every]
    want = [f"/a{r}/{i}" for r in range(6) for i in range(40)] + [f"/last/{i}" for i in range(5)]
    check(sorted(uris) == sorted(want), f"every request is in one file once: {len(uris)} lines for {len(want)} requests",
          sorted(set(want) - set(uris))[:5])
    check(len(rolled(d)) >= 5, f"with roll_keep 0, every rolled file is kept: {len(rolled(d))}")
finally:
    stop(p)

print("# no line is lost with steady traffic: the other workers write to a rolled file until they look")
d = os.path.join(TMP, "steady")
write_config(d, "            roll_size 4KiB\n            roll_keep 0\n            roll_keep_for 0")
p = start()
try:
    import threading
    sent, errors = [], []
    def steady(t, until):
        i = 0
        while time.time() < until:
            u = f"/s{t}/{i}"
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}{u}", timeout=5).read()
                sent.append(u)
            except Exception as e:
                errors.append(repr(e))
            i += 1
    until = time.time() + 5
    ts = [threading.Thread(target=steady, args=(t, until)) for t in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    check(not errors, "every request answered", errors[:3])
    check(wait_for(lambda: not glob.glob(f"{d}/*.gz.tmp") and all(f.endswith(".gz") for f in rolled(d)), 20), "all compressed")
    every = lines(os.path.join(d, "access.log"))
    for f in rolled(d):
        every += lines(os.path.join(d, f))
    uris = [json.loads(l.split(" ", 1)[1])["uri"] for l in every]
    check(len(rolled(d)) >= 3, f"it rolled while the requests came: {len(rolled(d))} files")
    check(sorted(uris) == sorted(sent), f"every request is in one file once: {len(uris)} lines for {len(sent)} requests",
          sorted(set(sent) - set(uris))[:5])
finally:
    stop(p)

print("# roll_keep_for removes older ones; roll_uncompressed leaves them plain")
d = os.path.join(TMP, "old")
os.makedirs(d)
old = os.path.join(d, "access-2001-01-01T00-00-00.000.log.gz")
other = os.path.join(d, "access-notes.log")
for f in (old, other):
    open(f, "w").close()
write_config(d, "            roll_size 4KiB\n            roll_keep 0\n            roll_keep_for 30d\n            roll_uncompressed")
p = start()
try:
    rounds(3, 40, "o")
    check(wait_for(lambda: not os.path.exists(old), 5), "a rolled file older than roll_keep_for is removed")
    check(os.path.exists(other), "a file that only looks like the log's is left alone")
    names = rolled(d)
    check(names and all(f.endswith(".log") for f in names), "roll_uncompressed leaves rolled files plain", names)
finally:
    stop(p)

print("# roll_local_time names them in local time")
d = os.path.join(TMP, "local")
write_config(d, "            roll_size 4KiB\n            roll_local_time\n            roll_uncompressed", workers=1)
p = start(env={"TZ": "XYZ-8"})   # POSIX: eight hours east of UTC
try:
    before = time.time()
    rounds(2, 40, "t")
    names = rolled(d)
    check(len(names) >= 1, "the file rolled", names)
    if names:
        m = ROLLED.match(names[0])
        # the name, read as UTC, is eight hours ahead of when it rolled
        as_utc = calendar.timegm(time.strptime("-".join(m.groups()[:6]), "%Y-%m-%d-%H-%M-%S"))
        check(abs(as_utc - 8 * 3600 - before) < 30, f"the name is local time: {names[0]}")
finally:
    stop(p)

print("# a file moved away is followed; roll_disabled renames nothing")
d = os.path.join(TMP, "moved")
write_config(d, "            roll_disabled")
p = start()
try:
    get(20, "before")
    time.sleep(0.3)
    os.rename(os.path.join(d, "access.log"), os.path.join(d, "access.log.1"))
    time.sleep(1.2)
    get(20, "after")
    check(wait_for(lambda: os.path.exists(os.path.join(d, "access.log")), 3), "the path is made again and written")
    now = lines(os.path.join(d, "access.log"))
    then = lines(os.path.join(d, "access.log.1"))
    check(sum("/after/" in l for l in now) >= 10, f"lines after the move go to the new file: {sum('/after/' in l for l in now)} of 20")
    check(sum("/before/" in l for l in then) == 20, "the moved file keeps the lines before")
    check(all("/before/" in l or "/after/" in l for l in now + then), "nothing else written")
    get(400, "big")
    time.sleep(1.2)
    get(5, "more")
    check(rolled(d) == [], "with roll_disabled nothing is renamed", rolled(d))
finally:
    stop(p)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
