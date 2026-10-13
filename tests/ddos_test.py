#!/usr/bin/env python3
"""
Functional tests for the per-IP connection guard (ip_guard) and trusted_proxies.

Starts a backend and a Limer instance per scenario, then drives raw sockets to
check: per-IP concurrent-connection caps, the new-connection rate limit, the
automatic ban that escalates from repeated rate-limit rejections, and that
trusted_proxies makes limits key on the X-Forwarded-For client rather than the
loopback peer.

    python3 tests/ddos_test.py        # from the repository root
"""
import json
import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "ddos")
os.makedirs(TMP, exist_ok=True)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
LB_PORT = 9610
BACKEND = 9611
PROCS = []
PASS = FAIL = 0


def ok(name):
    global PASS
    PASS += 1
    print(f"  ok   - {name}")


def bad(name, detail=""):
    global FAIL
    FAIL += 1
    print(f"  FAIL - {name}")
    if detail:
        print(f"         {detail}")


def wait_port(port, tries=100):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def start_limer(config):
    path = os.path.join(TMP, "Limerfile")
    with open(path, "w") as f:
        f.write(config)
    log = open(os.path.join(TMP, "limer.log"), "w")
    p = subprocess.Popen([BIN, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=log)
    PROCS.append(p)
    if not wait_port(LB_PORT):
        raise SystemExit("limer did not come up; see tests/tmp/ddos/limer.log")
    return p


def stop(p):
    p.terminate()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
    if p in PROCS:
        PROCS.remove(p)


def recv_all(s, timeout=1.0):
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    except OSError:
        pass
    return data


def request(headers_extra="", timeout=1.5, port=LB_PORT, path="/"):
    """One HTTP/1.1 request on a fresh connection. Returns (status:int|None, body:bytes)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    req = f"GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{headers_extra}\r\n"
    try:
        s.sendall(req.encode())
    except OSError:
        s.close()
        return None, b""
    data = recv_all(s, timeout)
    s.close()
    if not data:
        return None, b""
    try:
        status = int(data.split(b" ", 2)[1])
    except (IndexError, ValueError):
        status = None
    body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
    return status, body


# --------------------------------------------------------------------------
# Scenario A: max_conns_per_ip
# --------------------------------------------------------------------------
def test_max_conns():
    cfg = f"""{{
    admin off
    log_level error
    ip_guard {{
        max_conns_per_ip 3
    }}
}}
127.0.0.1:{LB_PORT} {{
    read_timeout 20s
    respond "ok"
}}
"""
    def held_refused(s):
        # Send a partial head so an admitted connection parks in CS_HEAD; then
        # a refused connection shows up as an immediate EOF/RST, an admitted one
        # as a short read timeout. Deterministic per connection.
        try:
            s.sendall(b"GET / HTTP/1.1\r\nHost: t\r\n")
        except OSError:
            return True
        s.settimeout(0.4)
        try:
            return s.recv(64) == b""   # EOF => closed at accept => refused
        except socket.timeout:
            return False               # held open => admitted
        except OSError:
            return True                # RST => refused

    p = start_limer(cfg)
    try:
        # Open connections one at a time, classifying each before the next, so
        # the count is unambiguous. The cap is 3: #4 is the first refusal.
        held = []
        admitted = 0
        refused_at = None
        for i in range(6):
            s = socket.create_connection(("127.0.0.1", LB_PORT), timeout=1)
            held.append(s)
            if held_refused(s):
                refused_at = i
                break
            admitted += 1
        if admitted == 3 and refused_at == 3:
            ok("max_conns_per_ip 3: 3 admitted, 4th refused")
        else:
            bad("max_conns_per_ip cap", f"admitted={admitted} first_refused_at={refused_at}")

        for s in held:
            s.close()
        time.sleep(0.3)

        # With the slots freed, a new request succeeds again.
        status, body = request()
        if status == 200 and b"ok" in body:
            ok("connection admitted again after slots freed")
        else:
            bad("connection admitted after slots freed", f"status={status} body={body[:60]!r}")
    finally:
        stop(p)


# --------------------------------------------------------------------------
# Scenario B: conn_rate (new-connection rate limit)
# --------------------------------------------------------------------------
def test_conn_rate():
    cfg = f"""{{
    admin off
    log_level error
    ip_guard {{
        conn_rate 5r/s
        conn_burst 5
    }}
}}
127.0.0.1:{LB_PORT} {{
    respond "ok"
}}
"""
    p = start_limer(cfg)
    try:
        # Open a burst of connections as fast as possible, then classify each.
        socks = []
        for _ in range(30):
            try:
                socks.append(socket.create_connection(("127.0.0.1", LB_PORT), timeout=1))
            except OSError:
                socks.append(None)
        admitted = refused = 0
        for s in socks:
            if s is None:
                refused += 1
                continue
            try:
                s.sendall(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                resp = recv_all(s, 1.0)
            except OSError:
                resp = b""
            finally:
                s.close()
            if resp:
                admitted += 1
            else:
                refused += 1
        if 1 <= admitted <= 12 and refused >= 12:
            ok(f"conn_rate burst 5: {admitted} admitted, {refused} refused of 30")
        else:
            bad("conn_rate limited the burst", f"admitted={admitted} refused={refused}")
    finally:
        stop(p)


# --------------------------------------------------------------------------
# Scenario C: automatic ban escalating from rate-limit rejections
# --------------------------------------------------------------------------
def test_ban_escalation():
    cfg = f"""{{
    admin off
    log_level error
    ip_guard {{
        ban_threshold 3
        ban_window 60s
        ban_duration 60s
    }}
}}
127.0.0.1:{LB_PORT} {{
    rate_limit {{
        key {{remote_ip}}
        rate 1r/m
        burst 1
    }}
    respond "ok"
}}
"""
    p = start_limer(cfg)
    try:
        statuses = []
        for _ in range(6):
            status, _ = request()
            statuses.append(status)
        # First request allowed, then rate-limited (429) strikes, then banned.
        # A banned direct client is refused at accept (None) or sent 403.
        saw_429 = 429 in statuses
        banned_tail = statuses[-1] in (None, 403)
        if statuses[0] == 200 and saw_429 and banned_tail:
            ok(f"rate-limit strikes escalate to a ban: {statuses}")
        else:
            bad("ban escalation", f"statuses={statuses}")
    finally:
        stop(p)


# --------------------------------------------------------------------------
# Scenario D: trusted_proxies keys limits on the XFF client, sets X-Real-IP
# --------------------------------------------------------------------------
def test_trusted_proxies():
    cfg = f"""{{
    admin off
    log_level error
    trusted_proxies 127.0.0.1
}}
127.0.0.1:{LB_PORT} {{
    rate_limit {{
        key {{remote_ip}}
        rate 1r/m
        burst 1
    }}
    reverse_proxy 127.0.0.1:{BACKEND}
}}
"""
    p = start_limer(cfg)
    try:
        # X-Real-IP forwarded upstream reflects the XFF client, not the peer.
        status, body = request("X-Forwarded-For: 9.9.9.9\r\n", path="/echo")
        real_ip = None
        try:
            hdrs = json.loads(body.decode())["headers"]
            real_ip = {k.lower(): v for k, v in hdrs.items()}.get("x-real-ip")
        except Exception:
            pass
        if status == 200 and real_ip == "9.9.9.9":
            ok("X-Real-IP upstream is the XFF client (9.9.9.9)")
        else:
            bad("X-Real-IP reflects XFF client", f"status={status} x-real-ip={real_ip}")

        # Same XFF client is rate-limited on its second request...
        s1a, _ = request("X-Forwarded-For: 1.1.1.1\r\n", path="/echo")
        s1b, _ = request("X-Forwarded-For: 1.1.1.1\r\n", path="/echo")
        # ...while a different XFF client still has its own bucket.
        s2, _ = request("X-Forwarded-For: 2.2.2.2\r\n", path="/echo")
        if s1a == 200 and s1b == 429 and s2 == 200:
            ok("rate_limit keys on the XFF client, not the loopback peer")
        else:
            bad("per-XFF-client rate limiting", f"1.1.1.1=({s1a},{s1b}) 2.2.2.2={s2}")
    finally:
        stop(p)


def main():
    backend = subprocess.Popen([sys.executable, "tests/backend.py", str(BACKEND), "b"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    PROCS.append(backend)
    wait_port(BACKEND)
    try:
        print("ip_guard / trusted_proxies tests")
        test_max_conns()
        test_conn_rate()
        test_ban_escalation()
        test_trusted_proxies()
    finally:
        for p in list(PROCS):
            try:
                p.terminate()
            except OSError:
                pass
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
