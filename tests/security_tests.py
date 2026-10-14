#!/usr/bin/env python3
"""
Black-box security tests for Limer.

Starts two normal backends, one scripted "hostile" upstream and a Limer
instance, then attacks the proxy over raw sockets: request smuggling vectors,
malformed framing, header injection and hygiene, forwarding-header spoofing,
resource limits (head size, body size, header count, connection count,
slowloris), hostile upstream responses, admin isolation and a wire-level
fuzz round. Every case must leave the proxy alive and answering.

    python3 tests/security_tests.py        # from the repository root
"""
import json
import os
import random
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "security")
os.makedirs(TMP, exist_ok=True)

LB = ("127.0.0.1", 9680)
ADMIN = ("127.0.0.1", 9699)
BACKEND_A, BACKEND_B, HOSTILE = 9601, 9602, 9603
MAX_BODY = 64 * 1024
READ_TIMEOUT = 2.0
IDLE_TIMEOUT = 1.5
MAX_CONNS = 40

CONFIG = f"""
{{
    admin 127.0.0.1:{ADMIN[1]}
    log_level warn
    max_connections {MAX_CONNS}
    grace 1s
}}

127.0.0.1:{LB[1]} {{
    max_body 64k
    read_timeout {READ_TIMEOUT}s
    idle_timeout {IDLE_TIMEOUT}s

    route redir {{
        match path /old/*
        redir https://example.com{{uri}} 302
    }}
    route hostile {{
        match path /hostile/*
        to 127.0.0.1:{HOSTILE}
        lb_retries 0
        max_fails 0
    }}
    route sticky {{
        match json type order
        to 127.0.0.1:{BACKEND_A} 127.0.0.1:{BACKEND_B}
        lb_policy hash json customer.id
    }}
    route placeholder {{
        match path /echo
        match header X-Inject-Test yes
        reverse_proxy 127.0.0.1:{BACKEND_A} {{
            header_up X-Tenant {{json.tenant}}
        }}
    }}
    reverse_proxy 127.0.0.1:{BACKEND_A} 127.0.0.1:{BACKEND_B} {{
        lb_retries 1
        max_fails 0
    }}
}}
"""

PROCS = []
PASS = FAIL = 0


def ok(name):
    global PASS
    PASS += 1
    print(f"  ok   - {name}")


def fail(name, detail=""):
    global FAIL
    FAIL += 1
    print(f"  FAIL - {name}")
    if detail:
        print(f"         {str(detail)[:400]}")


def check(name, cond, detail=""):
    if cond:
        ok(name)
    else:
        fail(name, detail)


# --------------------------------------------------------------------------
# scripted hostile upstream
# --------------------------------------------------------------------------

HOSTILE_RESPONSES = {
    b"/hostile/hop": (b"HTTP/1.1 200 OK\r\nConnection: close, X-Leak\r\nX-Leak: secret\r\n"
                      b"Keep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\nTrailer: X\r\n"
                      b"Content-Length: 2\r\n\r\nok"),
    b"/hostile/te-identity": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\nContent-Length: 2\r\n\r\nok",
    b"/hostile/clte": b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
    b"/hostile/badchunk": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nok\r\n0\r\n\r\n",
    b"/hostile/nul": b"HTTP/1.1 200 OK\r\nX-A: a\x00b\r\nContent-Length: 2\r\n\r\nok",
    b"/hostile/hugehead": b"HTTP/1.1 200 OK\r\nX-Big: " + b"a" * 70000 + b"\r\nContent-Length: 2\r\n\r\nok",
    b"/hostile/junkstatus": b"HTTP/1.1 9999 OK\r\nContent-Length: 2\r\n\r\nok",
    b"/hostile/notHTTP": b"SSH-2.0-OpenSSH\r\n\r\n",
    b"/hostile/short": b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort",
    b"/hostile/204body": b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello",
    b"/hostile/101": b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: evil\r\n\r\ninjected",
    b"/hostile/manyheaders": b"HTTP/1.1 200 OK\r\n" + b"".join(b"X-%d: v\r\n" % i for i in range(200)) + b"Content-Length: 2\r\n\r\nok",
    b"/hostile/obsfold": b"HTTP/1.1 200 OK\r\nX-A: a\r\n b\r\nContent-Length: 2\r\n\r\nok",
    b"/hostile/dup-cl": b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
}


def hostile_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", HOSTILE))
    srv.listen(64)
    while True:
        try:
            c, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=hostile_conn, args=(c,), daemon=True).start()


def hostile_conn(c):
    try:
        c.settimeout(3)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(65536)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\r\n", 1)[0]
        path = line.split(b" ")[1] if b" " in line else b"/"
        path = path.split(b"?")[0]
        if path == b"/hostile/hang":
            time.sleep(4)
            return
        if path == b"/hostile/drop":
            return
        resp = HOSTILE_RESPONSES.get(path, b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nhostile")
        c.sendall(resp)
        time.sleep(0.2)
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def connect(addr=LB, timeout=3.0):
    s = socket.create_connection(addr, timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def recv_all(s, timeout=3.0, limit=1 << 22):
    """Read until the peer closes or `timeout` of silence."""
    s.settimeout(timeout)
    data = b""
    while len(data) < limit:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data


def recv_response(s, timeout=3.0):
    """Read exactly one HTTP response (head + framed body)."""
    s.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, rest = data.split(b"\r\n\r\n", 1)
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
    first = head.split(b"\r\n")[0]
    method_head = False
    if b"content-length" in headers and not method_head:
        n = int(headers[b"content-length"])
        while len(rest) < n:
            chunk = s.recv(65536)
            if not chunk:
                break
            rest += chunk
        return head + b"\r\n\r\n" + rest[:n]
    if headers.get(b"transfer-encoding", b"").lower() == b"chunked":
        while not rest.endswith(b"0\r\n\r\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            rest += chunk
        return head + b"\r\n\r\n" + rest
    if first.split(b" ")[1:2] in ([b"204"], [b"304"], [b"101"]):
        return head + b"\r\n\r\n"
    return head + b"\r\n\r\n" + recv_all(s, timeout)


def raw(request: bytes, timeout=3.0, one=False):
    s = connect()
    try:
        try:
            s.sendall(request)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the proxy may answer (e.g. 413) and close before we finish sending
        return recv_response(s, timeout) if one else recv_all(s, timeout)
    finally:
        s.close()


def status_of(resp: bytes):
    try:
        return int(resp.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


def echo_headers(request: bytes):
    """Send a request to /echo through the proxy, return the headers the backend saw."""
    resp = raw(request, one=True)
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
    try:
        return status_of(resp), json.loads(body.decode())
    except ValueError:
        return status_of(resp), None


def alive(name):
    """The proxy must still answer normal traffic after every attack."""
    try:
        r = raw(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", one=True)
        a = raw(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", one=True) if False else b""
        check(f"{name}: proxy still alive", status_of(r) == 200, r[:120])
    except OSError as e:
        fail(f"{name}: proxy still alive", e)


def wait_port(port, tries=100):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


# --------------------------------------------------------------------------
# cases
# --------------------------------------------------------------------------

def t_smuggling():
    print("# request smuggling")
    smuggled = (b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n")
    r = raw(smuggled)
    check("CL + TE is rejected with 400", status_of(r) == 400, r[:100])
    check("CL + TE: connection closed, smuggled request never processed", r.count(b"HTTP/1.1") == 1 and b"smuggled" not in r, r)
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nContent-Length: 10\r\n\r\nabcd")
    check("conflicting Content-Length headers rejected", status_of(r) == 400, r[:100])
    for te in [b"chunked, gzip", b"gzip, chunked", b"xchunked", b"chunked\r\nTransfer-Encoding: chunked", b"identity"]:
        r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: " + te + b"\r\n\r\n0\r\n\r\n")
        check(f"Transfer-Encoding '{te.decode(errors='replace').splitlines()[0]}' rejected", status_of(r) == 400, r[:100])
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\nContent-Length: 1\r\n\r\nx")
    check("space before colon in header name rejected", status_of(r) == 400, r[:100])
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n chunked-ish fold\r\n\r\nx")
    check("obsolete line folding rejected", status_of(r) == 400, r[:100])
    for cl in [b"-1", b"+5", b"5x", b"0x10", b"99999999999999999999", b" 5 5"]:
        r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: " + cl + b"\r\n\r\n")
        check(f"Content-Length '{cl.decode()}' rejected", status_of(r) == 400, r[:100])
    # the backend must only ever see exactly one request per request we sent
    st, h = echo_headers(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde")
    check("Content-Length body forwarded with regenerated framing", st == 200 and h and h["body"] == "abcde" and h["headers"].get("Content-Length") == "5", h)
    st, h = echo_headers(b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\nX-Trailer: evil\r\n\r\n")
    check("chunked body is decoded; TE and trailers never reach the upstream", st == 200 and h and h["body"] == "abc"
          and "Transfer-Encoding" not in h["headers"] and "X-Trailer" not in h["headers"], h)
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\nabc\r\n0\r\n\r\n")
    check("invalid chunk size rejected", status_of(r) == 400, r[:100])
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3;ext=\"a\"\r\nabc\r\n0\r\n\r\n", one=True)
    check("chunk extensions are skipped", status_of(r) == 200 and b'"body": "abc"' in r, r[:200])
    alive("smuggling")


def t_malformed():
    print("# malformed requests")
    cases = [
        ("NUL byte in request target", b"GET /a\x00b HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("NUL byte in header", b"GET / HTTP/1.1\r\nHost: x\r\nX: a\x00b\r\n\r\n"),
        ("control char in target", b"GET /a\x01b HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("invalid header name", b"GET / HTTP/1.1\r\nHo(st: x\r\n\r\n"),
        ("empty header name", b"GET / HTTP/1.1\r\n: x\r\n\r\n"),
        ("HTTP/0.9 style", b"GET /\r\n\r\n"),
        ("HTTP/2.0 version", b"GET / HTTP/2.0\r\nHost: x\r\n\r\n"),
        ("garbage", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n"),
        ("double space in request line", b"GET  / HTTP/1.1\r\n\r\n"),
        ("missing target", b"GET HTTP/1.1\r\n\r\n"),
        ("8-bit method", b"G\xc3\x89T / HTTP/1.1\r\n\r\n"),
    ]
    for name, req in cases:
        r = raw(req)
        check(f"{name} -> 400", status_of(r) == 400, r[:100])
    # bodies with every byte value must not break JSON/form inspection
    body = bytes(range(256)) * 4
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body, one=True)
    check("binary body is inspected safely and forwarded", status_of(r) == 200 and b'"body_len": 1024' in r, r[:200])
    deep = b"[" * 30000 + b"]" * 30000
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(deep) + deep, one=True)
    check("deeply nested JSON body (30k levels) is handled", status_of(r) == 200, r[:100])
    deepobj = b'{"type":' * 7000 + b'"order"' + b"}" * 7000
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(deepobj) + deepobj, one=True)
    check("deeply nested JSON object with matching key is handled", status_of(r) == 200, r[:100])
    huge = b"[" * 400000 + b"]" * 400000
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(huge) + huge, one=True)
    check("800 KiB nested body rejected by max_body before inspection", status_of(r) == 413, r[:100])
    r = raw(b"GET http://evil.example/echo?x=1 HTTP/1.1\r\nHost: real.example\r\nConnection: close\r\n\r\n", one=True)
    check("absolute-form target is normalised to origin-form upstream", status_of(r) == 200 and b'"path": "/echo?x=1"' in r, r[:300])
    alive("malformed")


def t_limits():
    print("# resource limits")
    r = raw(b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: " + b"a" * 70000 + b"\r\n\r\n")
    check("oversized request head -> 431", status_of(r) == 431, r[:100])
    r = raw(b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
    check("oversized request line -> 431", status_of(r) == 431, r[:100])
    r = raw(b"GET / HTTP/1.1\r\n" + b"".join(b"X-%d: v\r\n" % i for i in range(300)) + b"\r\n")
    check("too many headers -> 400", status_of(r) == 400, r[:100])
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % (MAX_BODY + 1) + b"x" * 1000)
    check("Content-Length above max_body -> 413 before the body is read", status_of(r) == 413, r[:100])
    chunk = b"x" * 8192
    big = b"".join(b"%x\r\n%s\r\n" % (len(chunk), chunk) for _ in range(12)) + b"0\r\n\r\n"
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + big)
    check("chunked body above max_body -> 413 mid-stream", status_of(r) == 413, r[:100])
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFF\r\n" + b"x" * 100000)
    check("chunk size larger than max_body -> 413, not buffered", status_of(r) == 413, r[:100])
    r = raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFFFFF\r\n")
    check("overflowing chunk size -> 400", status_of(r) == 400, r[:100])
    # slowloris: partial head, then silence
    s = connect()
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")
    t0 = time.time()
    r = recv_all(s, timeout=READ_TIMEOUT + 2)
    dt = time.time() - t0
    s.close()
    check("slowloris head -> 408 after read_timeout", status_of(r) == 408 and dt < READ_TIMEOUT + 1.5, (r[:60], dt))
    s = connect()
    s.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc")
    r = recv_all(s, timeout=READ_TIMEOUT + 2)
    s.close()
    check("slow body -> 408 after read_timeout", status_of(r) == 408, r[:60])
    s = connect()
    t0 = time.time()
    r = recv_all(s, timeout=IDLE_TIMEOUT + 2)
    dt = time.time() - t0
    s.close()
    check("silent idle connection closed after idle_timeout", r == b"" and dt < IDLE_TIMEOUT + 1.5, (r[:40], dt))
    # pipelining flood: many requests in one write
    n = 300
    flood = b"".join(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n" for _ in range(n - 1)) + b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    r = raw(flood, timeout=5)
    check(f"{n} pipelined requests all answered", r.count(b"HTTP/1.1 200") == n, r.count(b"HTTP/1.1 200"))
    # connection limit
    socks = []
    try:
        for _ in range(MAX_CONNS + 10):
            socks.append(connect())
        time.sleep(0.3)
        refused = 0
        for s in socks[MAX_CONNS:]:
            s.settimeout(1)
            try:
                if s.recv(10) == b"":
                    refused += 1
            except socket.timeout:
                pass
            except OSError:
                refused += 1
        check("connections beyond max_connections are refused", refused >= 8, refused)
    finally:
        for s in socks:
            s.close()
    time.sleep(0.3)
    alive("limits")


def t_header_hygiene():
    print("# header hygiene")
    st, h = echo_headers(b"GET /echo HTTP/1.1\r\nHost: x\r\nConnection: close, X-Secret\r\nX-Secret: s3cr3t\r\n"
                         b"Keep-Alive: timeout=5\r\nTE: trailers\r\nProxy-Authorization: Basic abc\r\n"
                         b"Proxy-Connection: keep-alive\r\nUpgrade: h2c\r\nExpect: 100-continue\r\nTrailer: X\r\n\r\n")
    hdrs = h["headers"] if h else {}
    check("header nominated in Connection is not forwarded", "X-Secret" not in hdrs, hdrs)
    for hop in ["Keep-Alive", "TE", "Proxy-Authorization", "Proxy-Connection", "Trailer", "Expect"]:
        check(f"{hop} is stripped", hop not in hdrs, hdrs.get(hop))
    check("Upgrade not forwarded without a real upgrade request", "Upgrade" not in hdrs, hdrs.get("Upgrade"))
    check("upstream sees a proxy-owned Connection header", hdrs.get("Connection") == "keep-alive", hdrs.get("Connection"))
    st, h = echo_headers(b"GET /echo HTTP/1.1\r\nHost: victim.example\r\nX-Forwarded-For: 1.2.3.4\r\n"
                         b"X-Real-IP: 1.2.3.4\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: evil.example\r\nConnection: close\r\n\r\n")
    hdrs = h["headers"] if h else {}
    check("spoofed X-Forwarded-For is appended to, not trusted", hdrs.get("X-Forwarded-For") == "1.2.3.4, 127.0.0.1", hdrs.get("X-Forwarded-For"))
    check("spoofed X-Real-IP is overwritten", hdrs.get("X-Real-IP") == "127.0.0.1", hdrs.get("X-Real-IP"))
    check("spoofed X-Forwarded-Proto is overwritten", hdrs.get("X-Forwarded-Proto") == "http", hdrs.get("X-Forwarded-Proto"))
    check("spoofed X-Forwarded-Host is overwritten", hdrs.get("X-Forwarded-Host") == "victim.example", hdrs.get("X-Forwarded-Host"))
    r = raw(b"GET /old/x%0d%0aSet-Cookie:%20evil=1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", one=True)
    head = r.split(b"\r\n\r\n")[0]
    check("CRLF sequences in placeholders cannot split response headers",
          status_of(r) == 302 and b"\r\nSet-Cookie" not in head and b"%0d%0a" in head, head)
    r = raw(b"GET /old/x\r\nSet-Cookie: evil=1 HTTP/1.1\r\nHost: x\r\n\r\n")
    check("literal CRLF in the request line is rejected", status_of(r) == 400, r[:80])
    # decoded body/query/form/cookie placeholders used in a header must not carry CRLF to the upstream
    body = b'{"tenant":"a\\r\\nX-Injected: PWNED\\r\\nX-Smuggle: yes"}'
    st, h = echo_headers(b"POST /echo HTTP/1.1\r\nHost: x\r\nX-Inject-Test: yes\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    hdrs = h["headers"] if h else {}
    check("CRLF in a {json.X} placeholder cannot inject an upstream header",
          "X-Injected" not in hdrs and "X-Smuggle" not in hdrs, hdrs)
    check("the placeholder value is still delivered without its CRLF",
          hdrs.get("X-Tenant", "").startswith("a") and "\n" not in hdrs.get("X-Tenant", ""), hdrs.get("X-Tenant"))
    alive("header hygiene")


def t_hostile_upstream():
    print("# hostile upstream responses")
    r = raw(b"GET /hostile/hop HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", one=True)
    head = r.split(b"\r\n\r\n")[0].lower()
    check("upstream hop-by-hop headers are stripped from the client response",
          status_of(r) == 200 and b"x-leak" not in head and b"keep-alive:" not in head and b"proxy-authenticate" not in head
          and b"trailer" not in head, head)
    expect_502 = {
        "clte": "upstream response with CL and TE",
        "badchunk": "upstream chunked response with invalid size",
        "nul": "upstream response head with NUL byte",
        "hugehead": "upstream response head above 64 KiB",
        "junkstatus": "upstream response with 4-digit status",
        "notHTTP": "upstream speaking a different protocol",
        "manyheaders": "upstream response with 200 headers",
        "obsfold": "upstream response with obsolete folding",
        "dup-cl": "upstream response with conflicting Content-Length",
        "te-identity": "upstream response with Transfer-Encoding: identity",
        "101": "unsolicited 101 from upstream",
        "drop": "upstream closing without a response",
    }
    for path, name in expect_502.items():
        r = raw(b"GET /hostile/%s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % path.encode(), timeout=4)
        check(f"{name} -> 502", status_of(r) == 502, r[:120])
    r = raw(b"GET /hostile/short HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", timeout=4)
    check("truncated upstream body: connection closed, not padded", status_of(r) == 200 and r.endswith(b"short"), r[-40:])
    r = raw(b"GET /hostile/204body HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", timeout=4)
    check("204 with a body: body never forwarded", status_of(r) == 204 and b"hello" not in r, r)
    r = raw(b"GET /hostile/204body HTTP/1.1\r\nHost: x\r\n\r\nGET /hostile/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", timeout=4)
    check("stray bytes after a 204 do not poison the next response", r.count(b"HTTP/1.1 ") == 2 and b"hello" not in r, r)
    alive("hostile upstream")


def t_admin_isolation():
    print("# admin api isolation")
    for p in [b"/config", b"/upstreams", b"/metrics", b"/reload"]:
        r = raw(b"GET " + p + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", one=True)
        check(f"{p.decode()} on the public listener does not reach the admin API",
              b"lb_policy" not in r and b"limer_requests_total" not in r and b'"pools"' not in r and b"reload" not in r.lower(), r[:200])
    r = raw(b"POST /reload HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", one=True)
    check("POST /reload on the public listener is just proxied", b"reload scheduled" not in r, r[:200])
    s = connect(ADMIN)
    s.sendall(b"GET /config HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    r = recv_all(s)
    s.close()
    check("admin listener serves the config", b"lb_policy hash json customer.id" in r, r[:100])
    r = raw(b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", one=True)
    check("error pages do not echo the request path", b"/nope" not in r.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in r else True, r)
    alive("admin")


def t_client_misbehaviour():
    print("# misbehaving clients")
    s = connect()
    s.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nabc")
    s.close()
    s = connect()
    s.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab")
    s.close()
    s = connect()
    s.sendall(b"GET /hostile/hang HTTP/1.1\r\nHost: x\r\n\r\n")
    time.sleep(0.3)
    s.close()  # abandon while the upstream is still working
    s = connect()
    s.sendall(b"GET /echo HTTP/1.1\r\nHost: x\r\n\r\n")
    s.shutdown(socket.SHUT_WR)
    recv_all(s, timeout=2)
    s.close()
    try:
        s = connect()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        s.sendall(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
        time.sleep(0.1)
        s.close()  # RST while a 3 MiB response is streaming
    except OSError:
        pass
    time.sleep(0.5)
    alive("misbehaving clients")
    # concurrency with mixed hostile and normal traffic
    results = {"ok": 0}
    lock = threading.Lock()

    def worker(i):
        try:
            if i % 5 == 0:
                raw(b"GET /hostile/drop HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            elif i % 5 == 1:
                raw(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
            else:
                r = raw(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", one=True)
                if status_of(r) == 200:
                    with lock:
                        results["ok"] += 1
        except OSError:
            pass

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    check("mixed hostile/normal concurrent traffic: normal requests succeed", results["ok"] == 18, results)


def t_wire_fuzz():
    print("# wire-level fuzzing")
    rnd = random.Random(1234)
    seeds = [
        b"POST /echo?x=1 HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 24\r\nX-Tenant: acme\r\nCookie: sid=abc\r\n\r\n{\"type\":\"order\",\"id\":1}",
        b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
        b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        b"GET /hostile/hop HTTP/1.1\r\nHost: x\r\n\r\n",
    ]
    tokens = [b"\r\n", b"\n", b":", b" ", b"chunked", b"Content-Length: ", b"Transfer-Encoding: ", b"0\r\n\r\n", b"\x00",
              b"\xff", b"{", b"}", b"\"", b"\\u", b"99999999999", b"Connection: close", b"Host: ", b"HTTP/1.1", b"%0d%0a"]

    def mutate(b):
        b = bytearray(b)
        for _ in range(rnd.randint(1, 4)):
            op = rnd.randint(0, 4)
            pos = rnd.randint(0, len(b)) if b else 0
            if op == 0 and b:
                b[rnd.randrange(len(b))] = rnd.randint(0, 255)
            elif op == 1 and b:
                del b[pos:pos + rnd.randint(1, 8)]
            elif op == 2:
                b[pos:pos] = rnd.choice(tokens)
            elif op == 3 and b:
                b[pos:pos] = b[pos:pos + rnd.randint(1, 32)]
            else:
                del b[pos:]
        return bytes(b)

    errors = 0
    for i in range(1500):
        req = mutate(rnd.choice(seeds))
        try:
            s = connect(timeout=1.0)
            s.sendall(req)
            if rnd.random() < 0.3:
                s.close()
                continue
            s.settimeout(0.5)
            try:
                s.recv(4096)
            except (socket.timeout, OSError):
                pass
            s.close()
        except OSError:
            errors += 1
    check("1500 mutated requests sent", errors < 50, errors)
    time.sleep(0.5)
    alive("wire fuzz")
    s = connect(ADMIN)
    s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    r = recv_all(s)
    s.close()
    check("admin API healthy after fuzzing", b'"status":"ok"' in r, r[:100])


# --------------------------------------------------------------------------

def main():
    if not os.path.exists("./limer"):
        subprocess.check_call(["make", "-s"])
    for port, name in [(BACKEND_A, "a"), (BACKEND_B, "b")]:
        PROCS.append(subprocess.Popen([sys.executable, "tests/backend.py", str(port), name],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    threading.Thread(target=hostile_server, daemon=True).start()
    for port in (BACKEND_A, BACKEND_B, HOSTILE):
        if not wait_port(port):
            print("backend on port", port, "did not start")
            return 2
    cfg_path = os.path.join(TMP, "Limerfile")
    with open(cfg_path, "w") as f:
        f.write(CONFIG)
    log = open(os.path.join(TMP, "limer.log"), "w")
    lb = subprocess.Popen(["./limer", "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=log)
    PROCS.append(lb)
    if not wait_port(LB[1]):
        print("limer did not start; log:")
        log.close()
        print(open(os.path.join(TMP, "limer.log")).read())
        return 2
    try:
        for case in [t_smuggling, t_malformed, t_limits, t_header_hygiene, t_hostile_upstream,
                     t_admin_isolation, t_client_misbehaviour, t_wire_fuzz]:
            try:
                case()
            except Exception as e:  # a crashing test case is a failure, not an abort
                fail(f"{case.__name__} raised {type(e).__name__}", e)
            if lb.poll() is not None:
                fail("limer process is still running", f"exited with {lb.returncode}")
                break
        else:
            ok("limer process survived the whole suite")
    finally:
        lb.terminate()
        try:
            lb.wait(timeout=5)
        except subprocess.TimeoutExpired:
            lb.kill()
        log.close()
        for p in PROCS:
            if p.poll() is None:
                p.kill()
        text = open(os.path.join(TMP, "limer.log")).read()
        bad = [l for l in text.splitlines() if "Sanitizer" in l or "runtime error" in l]
        check("no sanitizer reports in the proxy log", not bad, bad[:3])
    print(f"\nsecurity tests: passed {PASS}, failed {FAIL}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
