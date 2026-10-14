#!/usr/bin/env python3
"""
Functional test for HTTP/3 (QUIC), using aioquic as an independent client.

Starts a backend and a limer instance with `http3` on a `tls internal` site,
then checks over HTTP/3: a local response, a proxied response with forwarding
headers, small and large request bodies, a large response, many concurrent
streams on one connection, the Alt-Svc advertisement over TCP, a reload, and a
graceful stop. Skips when aioquic is not installed (pip install aioquic).

    python3 tests/h3_test.py [path-to-limer]
"""
import asyncio
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import time

try:
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
except ImportError:
    print("h3 tests: skipped (aioquic not installed)")
    sys.exit(0)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "h3")
os.makedirs(TMP, exist_ok=True)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
PORT, BACKEND = 9930, 9931
AUTH = f"localhost:{PORT}".encode()
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


def check(cond, name, detail=""):
    (ok if cond else bad)(name, detail)


def wait_tcp(port, tries=200):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


class Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http = H3Connection(self._quic)
        self.pending = {}

    def quic_event_received(self, event):
        for ev in self.http.handle_event(event):
            if not isinstance(ev, (HeadersReceived, DataReceived)):
                continue
            st = self.pending.get(ev.stream_id)
            if not st:
                continue
            if isinstance(ev, HeadersReceived):
                st["headers"].extend(ev.headers)
            else:
                st["body"] += ev.data
            if ev.stream_ended and not st["fut"].done():
                st["fut"].set_result(st)

    async def request(self, method, path, body=None, headers=()):
        sid = self._quic.get_next_available_stream_id()
        hdrs = [(b":method", method.encode()), (b":scheme", b"https"),
                (b":authority", AUTH), (b":path", path.encode())]
        if body is not None:
            hdrs.append((b"content-length", str(len(body)).encode()))
        hdrs += list(headers)
        fut = asyncio.get_running_loop().create_future()
        self.pending[sid] = {"headers": [], "body": b"", "fut": fut}
        self.http.send_headers(sid, hdrs, end_stream=body is None)
        if body is not None:
            self.http.send_data(sid, body, end_stream=True)
        self.transmit()
        st = await asyncio.wait_for(fut, 30)
        h = {k.decode(): v.decode() for k, v in st["headers"]}
        return int(h.get(":status", 0)), h, st["body"]


def quic_config():
    return QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                             verify_mode=ssl.CERT_NONE, server_name="localhost")


async def session(fn):
    async with connect("127.0.0.1", PORT, configuration=quic_config(), create_protocol=Client) as c:
        return await fn(c)


async def main_tests():
    # 1) a local response
    status, h, body = await session(lambda c: c.request("GET", "/static"))
    check(status == 200 and body == b"hello over h3", "local response over HTTP/3", f"{status} {body[:40]!r}")

    # 2) a proxied response; forwarding headers reach the backend
    async def proxied(c):
        return await c.request("GET", "/echo?x=1", headers=[(b"x-test", b"h3")])
    status, h, body = await session(proxied)
    try:
        j = json.loads(body)
        hdrs = {k.lower(): v for k, v in j["headers"].items()}
    except Exception:
        j, hdrs = {}, {}
    check(status == 200 and j.get("name") == "b", "proxied response over HTTP/3", f"{status} {body[:80]!r}")
    check(hdrs.get("x-test") == "h3", "request headers are forwarded")
    check(hdrs.get("x-forwarded-proto") == "https" and hdrs.get("x-real-ip") == "127.0.0.1",
          "forwarding headers are set (proto https, real ip)", str({k: hdrs.get(k) for k in ("x-forwarded-proto", "x-real-ip")}))
    check(j.get("path") == "/echo?x=1" or j.get("path") == "/echo", "path and query reach the backend", str(j.get("path")))

    # 3) request bodies, small and larger than the initial window
    async def bodies(c):
        small = await c.request("POST", "/echo", body=b'{"hello":"h3"}')
        big = await c.request("POST", "/echo", body=os.urandom(64) * 3200)  # ~200 KB
        return small, big
    (s1, _, b1), (s2, _, b2) = await session(bodies)
    try:
        e1 = json.loads(b1).get("body")
        e2len = len(json.loads(b2).get("body", ""))
    except Exception:
        e1, e2len = None, -1
    check(s1 == 200 and e1 == '{"hello":"h3"}', "small POST body arrives intact", f"{s1} {str(e1)[:60]}")
    check(s2 == 200 and e2len > 0, "a ~200 KB POST body is accepted and forwarded", f"{s2} echoed {e2len}")

    # 4) a large response (exercises flow control and acknowledgement-driven chunk freeing)
    t0 = time.time()
    status, h, body = await session(lambda c: c.request("GET", "/big"))
    check(status == 200 and len(body) == 3 * 1024 * 1024, "3 MiB response arrives complete",
          f"{status} {len(body)} bytes in {time.time() - t0:.2f}s")

    # 5) many concurrent streams on one connection
    async def many(c):
        return await asyncio.gather(*(c.request("GET", f"/echo?i={i}") for i in range(20)))
    res = await session(many)
    check(all(r[0] == 200 for r in res), "20 concurrent streams on one connection", str([r[0] for r in res]))

    # 6) a response without content ends the stream on the HEADERS frame. (A reply to HEAD
    #    does too, keeping the GET's content-length as RFC 9114 4.1.2 allows; aioquic 1.6
    #    rejects that as a length mismatch, so it is not exercised here.)
    status, h, body = await session(lambda c: c.request("GET", "/empty"))
    check(status == 204 and body == b"", "a 204 response has no body", f"{status} {len(body)}")


def alt_svc():
    out = subprocess.run(["curl", "-sk", "-D", "-", "-o", "/dev/null", f"https://localhost:{PORT}/static"],
                         capture_output=True, text=True, timeout=10).stdout.lower()
    check(f'alt-svc: h3=":{PORT}"' in out, "HTTPS over TCP advertises HTTP/3 with Alt-Svc", out.strip()[-120:])


def main():
    backend = subprocess.Popen([sys.executable, "tests/backend.py", str(BACKEND), "b"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_tcp(BACKEND)
    cfg = os.path.join(TMP, "Limerfile")
    with open(cfg, "w") as f:
        f.write(f"""{{
    admin off
    log_level info
    http3
}}
localhost:{PORT} {{
    handle /static {{
        respond "hello over h3"
    }}
    handle /empty {{
        respond 204
    }}
    reverse_proxy 127.0.0.1:{BACKEND}
}}
""")
    log = open(os.path.join(TMP, "limer.log"), "w")
    p = subprocess.Popen([BIN, "run", "-c", cfg], stdout=subprocess.DEVNULL, stderr=log)
    try:
        if not wait_tcp(PORT):
            raise SystemExit("limer did not come up")
        time.sleep(0.5)
        print("http/3 tests")
        asyncio.run(main_tests())
        alt_svc()

        # 7) a reload rebuilds the QUIC side and new connections keep working
        p.send_signal(signal.SIGHUP)
        time.sleep(1.0)
        status, _, body = asyncio.run(session(lambda c: c.request("GET", "/static")))
        check(status == 200 and body == b"hello over h3", "HTTP/3 works after a reload", f"{status}")

        text = open(os.path.join(TMP, "limer.log")).read()
        check("http/3: listening on" in text, "the UDP listener was opened")
        check("AddressSanitizer" not in text and "runtime error" not in text, "no sanitizer reports")
    finally:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=15)
            check(True, "graceful stop")
        except subprocess.TimeoutExpired:
            p.kill()
            check(False, "graceful stop", "limer did not exit")
        backend.terminate()

    print(f"\nhttp/3 tests: passed {PASS}, failed {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
