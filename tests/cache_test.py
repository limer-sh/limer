#!/usr/bin/env python3
"""
Response-cache correctness, from FEEDBACK1.md.

A test origin whose bodies count its own hits and vary by request, behind two
Limer sites with a `cache` block, checks that:

 - an origin-compressed answer is never served as garbage (problem 1)
 - repeated Cache-Control / Vary lines are honoured (problem 2)
 - two sites on one host name keep their entries apart (problem 3)
 - `ttl` is not applied to invalid/expired freshness or to Cookie'd requests (problem 4)
 - `no-cache` revalidates every time (problem 5)
 - `must-revalidate` / `s-maxage` are never served stale (problem 6)

    python3 tests/cache_test.py        # from the repository root
"""
import gzip
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "cache")
os.makedirs(TMP, exist_ok=True)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
A, B, C, ADMIN = 9960, 9961, 9965, 9964  # two sites, one encode site, admin
O1, O2 = 9962, 9963        # two origins (for the two-site test)
PASS = FAIL = 0
HITS = {}
LOCK = threading.Lock()
BIG = b"<html><body>" + b"quillo " * 600 + b"</body></html>"


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


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, body, hdrs):
        self.send_response(code)
        for k, v in hdrs:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        with LOCK:
            HITS[p] = HITS.get(p, 0) + 1
            n = HITS[p]
        tag = self.server.tag
        inm = self.headers.get("If-None-Match")
        ck = self.headers.get("Cookie", "none")
        text = ("Content-Type", "text/plain")
        if p == "/name":
            return self.send(200, tag.encode(), [("Cache-Control", "max-age=300")])
        if p == "/nc":
            cc, et = ("Cache-Control", "no-cache"), ("ETag", '"n1"')
            if inm == '"n1"':
                return self.send(304, b"", [et, cc])
            return self.send(200, b"v%d" % n, [et, cc, text])
        if p == "/mr":
            return self.send(200, b"v%d" % n, [("Cache-Control", "max-age=1, must-revalidate"), text])
        if p == "/two-cc":
            return self.send(200, ("for %s" % ck).encode(),
                             [("Cache-Control", "max-age=60"), ("Cache-Control", "private"), text])
        if p == "/two-vary":
            return self.send(200, ("for %s" % ck).encode(),
                             [("Cache-Control", "public, max-age=60"), ("Vary", "Accept-Encoding"), ("Vary", "Cookie"), text])
        if p == "/exp0":
            return self.send(200, b"v%d" % n, [("Expires", "0"), text])
        if p == "/neg":
            return self.send(200, b"v%d" % n, [("Cache-Control", "max-age=-1"), text])
        if p == "/page":
            return self.send(200, ("<p>for %s</p>" % ck).encode(), [("Content-Type", "text/html")])
        if p == "/gz":
            h = [("Cache-Control", "max-age=60"), ("Vary", "Accept-Encoding"), ("Content-Type", "text/html")]
            if "gzip" in self.headers.get("Accept-Encoding", ""):
                return self.send(200, gzip.compress(BIG), h + [("Content-Encoding", "gzip")])
            return self.send(200, BIG, h)
        self.send(404, b"no", [])


def serve(port, tag):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Origin)
    srv.tag = tag
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def wait_tcp(port, tries=200):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def req(port, path, headers=None, body=False):
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            raw = resp.read()
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, raw
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def raw_get(port, path, headers=None):
    """Raw socket GET so we see the exact bytes (no client-side gunzip)."""
    hdr = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{hdr}\r\n".encode())
    out = b""
    try:
        while True:
            b = s.recv(4096)
            if not b:
                break
            out += b
    except OSError:
        pass
    s.close()
    head, _, body = out.partition(b"\r\n\r\n")
    return head.decode("latin1"), body


def main():
    serve(O1, "site A")
    serve(O2, "site B")
    cfg = os.path.join(TMP, "Limerfile")
    with open(cfg, "w") as f:
        f.write(f"""{{
    admin 127.0.0.1:{ADMIN}
    log_level warn
    storage {TMP}/storage
}}
http://127.0.0.1:{A} {{
    cache {{
        ttl 5m
        stale 30s
    }}
    reverse_proxy 127.0.0.1:{O1}
}}
http://127.0.0.1:{B} {{
    cache {{
        ttl 5m
    }}
    reverse_proxy 127.0.0.1:{O2}
}}
http://127.0.0.1:{C} {{
    encode gzip
    cache {{
        ttl 5m
    }}
    reverse_proxy 127.0.0.1:{O1}
}}
""")
    log = open(os.path.join(TMP, "limer.log"), "w")
    p = subprocess.Popen([BIN, "run", "-c", cfg, "-w", "1"], stdout=subprocess.DEVNULL, stderr=log)
    try:
        if not (wait_tcp(A) and wait_tcp(B)):
            raise SystemExit("limer did not come up")

        print("problem 1: an origin-compressed answer is never served as garbage")
        raw_get(A, "/gz", {"Accept-Encoding": "gzip"})  # fill
        head, body = raw_get(A, "/gz", {"Accept-Encoding": "gzip"})
        has_ce = "content-encoding: gzip" in head.lower()
        looks_gzip = body[:2] == b"\x1f\x8b"
        # either the body is gzip WITH the header, or it is plain; never gzip WITHOUT the header
        check(not (looks_gzip and not has_ce), "a gzip body is never sent without Content-Encoding",
              f"gzip_body={looks_gzip} has_ce={has_ce}")
        # and the decoded content is the real page
        decoded = gzip.decompress(body) if looks_gzip else body
        check(decoded == BIG, "the body decodes to the original page")

        print("problem 2: repeated Cache-Control / Vary lines are honoured")
        _, _, a1 = req(A, "/two-cc", {"Cookie": "ana"})
        _, _, b1 = req(A, "/two-cc", {"Cookie": "bob"})
        check(a1 == b"for ana" and b1 == b"for bob", "Cache-Control: private on a 2nd line is seen", f"{a1} {b1}")
        _, _, a2 = req(A, "/two-vary", {"Cookie": "ana"})
        _, _, b2 = req(A, "/two-vary", {"Cookie": "bob"})
        check(a2 == b"for ana" and b2 == b"for bob", "Vary: Cookie on a 2nd line is seen", f"{a2} {b2}")

        print("problem 3: two sites on one host name keep entries apart")
        _, _, s1 = req(A, "/name")
        _, _, s2 = req(B, "/name")
        check(s1 == b"site A" and s2 == b"site B", "each site serves its own origin", f"{s1} {s2}")

        print("problem 4: ttl is not applied where it must not be")
        _, _, pa = req(A, "/page", {"Cookie": "ana"})
        _, _, pb = req(A, "/page", {"Cookie": "bob"})
        check(pa == b"<p>for ana</p>" and pb == b"<p>for bob</p>", "a Cookie'd page is not cached under ttl", f"{pa} {pb}")
        _, _, e1 = req(A, "/exp0")
        _, _, e2 = req(A, "/exp0")
        check(e1 != e2, "Expires: 0 is not cached (treated as expired)", f"{e1} {e2}")
        _, _, n1 = req(A, "/neg")
        _, _, n2 = req(A, "/neg")
        check(n1 != n2, "max-age=-1 is not cached (treated as expired)", f"{n1} {n2}")

        print("problem 5: no-cache revalidates every time")
        before = HITS.get("/nc", 0)
        for _ in range(12):
            req(A, "/nc")
        hit = HITS.get("/nc", 0) - before
        check(hit == 12, "every no-cache request reaches the origin", f"origin hits={hit}/12")

        print("problem 6: must-revalidate is never served stale")
        req(A, "/mr")
        time.sleep(1.4)
        head, _ = raw_get(A, "/mr")
        check("x-cache: stale" not in head.lower(), "must-revalidate is not served stale", head.split("\r\n")[0] + " ...")

        print("problems 1b/7: a compressing origin is cached and compressed per client")
        raw_get(C, "/gz", {"Accept-Encoding": "gzip"})  # fill (origin would compress; limer asks identity)
        head, body = raw_get(C, "/gz", {"Accept-Encoding": "gzip"})
        is_hit = "x-cache: hit" in head.lower()
        is_gz = "content-encoding: gzip" in head.lower() and body[:2] == b"\x1f\x8b"
        check(is_hit and is_gz, "a gzip client gets a cached, correctly-encoded answer", head.split(chr(13))[0])
        check(gzip.decompress(body) == BIG, "the cached gzip body decodes to the original")
        phead, pbody = raw_get(C, "/gz", {"Accept-Encoding": "identity"})
        check("x-cache: hit" in phead.lower() and pbody == BIG, "a plain client is served the same entry, uncompressed")
        before = HITS.get("/gz2", 0)
        for e in ("gzip, deflate, br, zstd", "gzip, deflate, br", "gzip, deflate"):
            raw_get(C, "/gz2", {"Accept-Encoding": e})
        check(HITS.get("/gz2", 0) - before == 1, "varied Accept-Encoding strings do not thrash the cache",
              f"origin hits={HITS.get('/gz2', 0) - before}")

        print("problem 8: the cache can be purged")
        import json as _json
        def purge(q):
            r = urllib.request.Request(f"http://127.0.0.1:{ADMIN}/cache/purge?{q}", method="POST")
            try:
                with urllib.request.urlopen(r, timeout=5) as resp:
                    return resp.status, _json.loads(resp.read() or b"{}")
            except urllib.error.HTTPError as e:
                return e.code, {}
        # warm a cacheable entry (max-age via /name), confirm HIT, purge, confirm MISS
        raw_get(A, "/name")
        h1, _ = raw_get(A, "/name")
        check("x-cache: hit" in h1.lower(), "an entry is a HIT before purge", h1.split(chr(13))[0])
        st, j = purge("path=/name")
        check(st == 200 and j.get("removed") >= 1, "POST /cache/purge removes the entry", f"{st} {j}")
        h2, _ = raw_get(A, "/name")
        check("x-cache: miss" in h2.lower(), "the purged path is a MISS again", h2.split(chr(13))[0])
        # prefix purge
        raw_get(A, "/name")
        st, j = purge("prefix=/na")
        check(st == 200 and j.get("removed") >= 1, "a prefix purge removes matching entries", j)
        st, _ = purge("")
        check(st == 400, "a purge with no host or path is refused", f"{st}")

        text = open(os.path.join(TMP, "limer.log")).read()
        check("AddressSanitizer" not in text and "runtime error" not in text, "no sanitizer reports")
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()

    print(f"\ncache tests: passed {PASS}, failed {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
