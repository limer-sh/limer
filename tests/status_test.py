#!/usr/bin/env python3
"""
Functional test for retry_status and redirect_on.

Two backends disagree about which objects exist: A answers 404 for /on-b and
503 for /flaky, B has everything; both answer 404 for /nowhere. With
`lb_policy first` every request goes to A first, so:

  - retry_status 404 503 makes limer try B and return B's answer;
  - without it, A's 404 reaches the client;
  - when every backend answers 404, the 404 passes through, or with
    redirect_on the client gets a redirect instead.

    python3 tests/status_test.py        # from the repository root
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
TMP = os.path.join("tests", "tmp", "status")
os.makedirs(TMP, exist_ok=True)

BIN = sys.argv[1] if len(sys.argv) > 1 else "./limer"
A, B = 9941, 9942
RETRY, PLAIN, REDIR = 9940, 9943, 9944
PASS = FAIL = 0
hits = {"a": 0, "b": 0}


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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _answer(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        name = self.server.name
        hits[name] += 1
        if self.path.startswith("/nowhere"):
            code = 404
        elif self.path.startswith("/on-b") and name != "b":
            code = 404
        elif self.path.startswith("/flaky") and name == "a":
            code = 503
        else:
            code = 200
        out = json.dumps({"name": name, "len": len(body), "path": self.path}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_HEAD = _answer

    def log_message(self, *a):
        pass


def serve(port, name):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.name = name
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def wait_tcp(port, tries=200):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def fetch(port, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                 method="POST" if body is not None else "GET")
    try:
        with OPENER.open(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def name_of(body):
    try:
        return json.loads(body).get("name")
    except ValueError:
        return None


def main():
    serve(A, "a")
    serve(B, "b")
    cfg = os.path.join(TMP, "Limerfile")
    with open(cfg, "w") as f:
        f.write(f"""{{
    admin off
    log_level warn
}}
127.0.0.1:{RETRY} {{
    reverse_proxy 127.0.0.1:{A} 127.0.0.1:{B} {{
        lb_policy first
        retry_status 404 503
    }}
}}
127.0.0.1:{PLAIN} {{
    reverse_proxy 127.0.0.1:{A} 127.0.0.1:{B} {{
        lb_policy first
    }}
}}
127.0.0.1:{REDIR} {{
    reverse_proxy 127.0.0.1:{A} 127.0.0.1:{B} {{
        lb_policy first
        retry_status 404
        redirect_on 404 /search?q={{path}}
    }}
}}
""")
    log = open(os.path.join(TMP, "limer.log"), "w")
    p = subprocess.Popen([BIN, "run", "-c", cfg], stdout=subprocess.DEVNULL, stderr=log)
    try:
        if not all(wait_tcp(port) for port in (RETRY, PLAIN, REDIR)):
            raise SystemExit("limer did not come up")
        print("retry_status / redirect_on tests")

        s, _, b = fetch(PLAIN, "/on-b")
        check(s == 404 and name_of(b) == "a", "without retry_status, the first upstream's 404 reaches the client", f"{s} {b[:60]!r}")

        s, _, b = fetch(RETRY, "/on-b")
        check(s == 200 and name_of(b) == "b", "retry_status 404: the next upstream answers instead", f"{s} {b[:60]!r}")

        s, _, b = fetch(RETRY, "/flaky")
        check(s == 200 and name_of(b) == "b", "retry_status 503: a 503 is retried too", f"{s} {b[:60]!r}")

        s, _, b = fetch(RETRY, "/on-b", body=b'{"order":42}')
        try:
            j = json.loads(b)
        except ValueError:
            j = {}
        check(s == 200 and j.get("name") == "b" and j.get("len") == 12,
              "a buffered POST body is replayed intact on the retry", f"{s} {b[:60]!r}")

        before = dict(hits)
        s, _, b = fetch(RETRY, "/nowhere")
        tried = (hits["a"] - before["a"], hits["b"] - before["b"])
        check(s == 404, "when every upstream answers 404, the 404 is passed through", f"{s}")
        check(tried == (1, 1), "each upstream was asked exactly once", f"asked a,b = {tried}")

        s, h, b = fetch(REDIR, "/nowhere")
        loc = {k.lower(): v for k, v in h.items()}.get("location")
        check(s == 302 and loc == "/search?q=/nowhere", "redirect_on 404: the final 404 becomes a redirect",
              f"{s} location={loc}")

        s, _, b = fetch(REDIR, "/on-b")
        check(s == 200 and name_of(b) == "b", "with redirect_on, a retry that succeeds is not redirected", f"{s}")

        s, _, b = fetch(REDIR, "/exists")
        check(s == 200 and name_of(b) == "a", "responses that are not listed pass through untouched", f"{s}")

        text = open(os.path.join(TMP, "limer.log")).read()
        check("AddressSanitizer" not in text and "runtime error" not in text, "no sanitizer reports")
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()

    print(f"\nstatus tests: passed {PASS}, failed {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
