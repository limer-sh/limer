#!/usr/bin/env bash
# Integration tests for Limer. Requires python3 and curl.
set -u
cd "$(dirname "$0")/.."
# macOS: these scripts use GNU coreutils and sed (brew install coreutils gnu-sed)
if [ "$(uname -s)" = Darwin ]; then
    for d in /opt/homebrew/opt/coreutils/libexec/gnubin /opt/homebrew/opt/gnu-sed/libexec/gnubin \
             /usr/local/opt/coreutils/libexec/gnubin /usr/local/opt/gnu-sed/libexec/gnubin; do
        [ -d "$d" ] && PATH="$d:$PATH"
    done
fi
BIN=./limer
TMP=tests/tmp
rm -rf "$TMP"; mkdir -p "$TMP"
PASS=0; FAIL=0
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    wait 2>/dev/null
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL - $1"; [ -n "${2:-}" ] && echo "         $2"; }
check() { # name, condition-result, detail
    if [ "$2" = "0" ]; then ok "$1"; else fail "$1" "${3:-}"; fi
}
expect_eq() { # name actual expected
    if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "expected '$3', got '$2'"; fi
}
expect_contains() { # name haystack needle
    case "$2" in *"$3"*) ok "$1";; *) fail "$1" "missing '$3' in: ${2:0:300}";; esac
}

wait_port() { # port
    for _ in $(seq 1 100); do
        if curl -s -o /dev/null "http://127.0.0.1:$1/" 2>/dev/null; then return 0; fi
        sleep 0.05
    done
    return 1
}

start_backend() { # port name [args...]
    python3 tests/backend.py "$@" &
    PIDS+=($!)
}

echo "# building"
make -s || { echo "build failed"; exit 1; }

echo "# starting backends"
for p in 9101 9102 9103 9111 9112 9121 9131 9180; do
    if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then
        echo "port $p is already in use by another program; free it and re-run"; exit 1
    fi
done
start_backend 9101 a
start_backend 9102 b
start_backend 9103 c
start_backend 9111 orders1
start_backend 9112 orders2
start_backend 9121 slow --slow 3
start_backend 9131 sick --fail-health
for p in 9101 9102 9103 9111 9112 9121 9131; do wait_port $p || { echo "backend $p did not start"; exit 1; }; done

cat > "$TMP/Limerfile" <<'CFG'
{
    admin 127.0.0.1:9199
    log_level warn
    pidfile tests/tmp/limer.pid
    grace 2s
}

127.0.0.1:9180 {
    max_body 1m
    read_timeout 2s
    log

    route ping {
        match path /ping
        respond 200 "pong"
    }

    route json-status {
        match path /api/status
        respond 503 `{"status":"maintenance"}`
    }

    route go-away {
        match path /old/*
        redir https://example.com{uri} 301
    }

    # Payload-based routing: JSON field decides the pool
    route orders {
        match method POST
        match json type == order refund
        to 127.0.0.1:9111 127.0.0.1:9112
        lb_policy hash json customer.id
        header_up X-Route orders
        header_down X-Served-By {upstream_hostport}
    }

    route vip {
        match json amount > 1000
        to 127.0.0.1:9103
        header_up X-Route vip
    }

    route by-form {
        match form action == checkout
        to 127.0.0.1:9103
    }

    route by-regex {
        match body ~ "priority=(high|urgent)"
        to 127.0.0.1:9103
    }

    route by-header {
        match header X-Tenant acme
        to 127.0.0.1:9102
    }

    route sticky {
        match path /sticky/*
        to 127.0.0.1:9101 127.0.0.1:9102 127.0.0.1:9103
        lb_policy header X-Session
    }

    route cookie-sticky {
        match path /cookie
        to 127.0.0.1:9101 127.0.0.1:9102 127.0.0.1:9103
        lb_policy hash cookie sid
    }

    route slow {
        match path /slow
        to 127.0.0.1:9121
        response_timeout 1s
        lb_retries 0
    }

    route dead {
        match path /dead
        to 127.0.0.1:9191 127.0.0.1:9192
        connect_timeout 1s
    }

    route failover {
        match path /failover
        to 127.0.0.1:9191 127.0.0.1:9101
        lb_policy first
    }

    route sick {
        match path /sick
        to 127.0.0.1:9131 127.0.0.1:9101
        health_uri /healthz
        health_interval 0.5s
    }

    route drop {
        match path /drop
        to 127.0.0.1:9101
        lb_retries 0
    }

    route weighted {
        match path /weighted
        to 127.0.0.1:9101 weight=3 127.0.0.1:9102 weight=1
    }

    route least {
        match path /least
        to 127.0.0.1:9101 127.0.0.1:9102
        lb_policy least_conn
    }

    route notrailing {
        match path /none
        match not remote_ip 127.0.0.0/8
        respond 418 "unreachable"
    }

    reverse_proxy 127.0.0.1:9101 127.0.0.1:9102 127.0.0.1:9103 {
        lb_policy round_robin
        health_uri /healthz
        health_interval 0.5s
        header_up X-Forwarded-Proto-Test {scheme}
    }
}

127.0.0.1:9181 {
    reverse_proxy 127.0.0.1:9101
}

127.0.0.1:9184 {
    route {
        match path /only
        respond "only"
    }
}
CFG

echo "# validating config"
out=$($BIN validate -c "$TMP/Limerfile" 2>&1); rc=$?
check "validate accepts test config" $rc "$out"

printf ':9999 {\n  reverse_proxy {\n    lb_policy bogus\n  }\n}\n' > "$TMP/bad.conf"
out=$($BIN validate -c "$TMP/bad.conf" 2>&1); rc=$?
check "validate rejects bad policy" $([ $rc -ne 0 ] && echo 0 || echo 1) "$out"
expect_contains "validate error mentions line" "$out" "line 3"

printf ':9999 {\n  reverse_proxy 127.0.0.1:1 {\n    header_up\n' > "$TMP/bad2.conf"
out=$($BIN validate -c "$TMP/bad2.conf" 2>&1); rc=$?
check "validate rejects unterminated block" $([ $rc -ne 0 ] && echo 0 || echo 1) "$out"

echo "# starting limer"
$BIN run -c "$TMP/Limerfile" >"$TMP/access.log" 2>"$TMP/limer.log" &
LIMER=$!
PIDS+=($LIMER)
wait_port 9180 || { echo "limer did not start"; cat "$TMP/limer.log"; exit 1; }
sleep 0.7   # let health checks run once

B="http://127.0.0.1:9180"
H() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "# basic proxying"
expect_eq "respond directive" "$(curl -s $B/ping)" "pong"
expect_eq "respond status" "$(H $B/api/status)" "503"
expect_eq "respond json content-type" "$(curl -s -D - -o /dev/null $B/api/status | grep -i '^content-type' | tr -d '\r' | awk '{print $2}')" "application/json"
hdrs=$(curl -s -D - -o /dev/null "$B/old/thing?x=1")
expect_contains "redirect status" "$hdrs" "HTTP/1.1 301"
expect_contains "redirect location with placeholder" "$hdrs" "Location: https://example.com/old/thing?x=1"

names=""
for i in 1 2 3 4 5 6; do names="$names $(curl -s $B/)"; done
expect_contains "round robin reaches a" "$names" "hello from a"
expect_contains "round robin reaches b" "$names" "hello from b"
expect_contains "round robin reaches c" "$names" "hello from c"
seq=$(for i in 1 2 3; do echo "$(curl -s $B/)" | sed 's/hello from //'; done | tr '\n' ' ')
case "$seq" in "a b c "|"b c a "|"c a b ") ok "round robin is sequential ($seq)";; *) fail "round robin is sequential" "$seq";; esac

echo "# forwarded headers"
echo_out=$(curl -s -H 'Host: myhost.example' $B/echo)
expect_contains "Host preserved" "$echo_out" '"Host": "myhost.example"'
expect_contains "X-Forwarded-For set" "$echo_out" '"X-Forwarded-For": "127.0.0.1"'
expect_contains "X-Forwarded-Proto set" "$echo_out" '"X-Forwarded-Proto": "http"'
expect_contains "X-Real-IP set" "$echo_out" '"X-Real-IP": "127.0.0.1"'
expect_contains "header_up placeholder" "$echo_out" '"X-Forwarded-Proto-Test": "http"'
echo_out=$(curl -s -H 'X-Forwarded-For: 10.1.1.1' $B/echo)
expect_contains "X-Forwarded-For appended" "$echo_out" '"X-Forwarded-For": "10.1.1.1, 127.0.0.1"'

echo "# payload-based routing"
r1=$(curl -s -X POST -H 'Content-Type: application/json' -d '{"type":"order","customer":{"id":"c-1"}}' $B/echo)
expect_contains "json route selects orders pool" "$r1" '"name": "orders'
expect_contains "header_up on route" "$r1" '"X-Route": "orders"'
r1h=$(curl -s -D - -o /dev/null -X POST -d '{"type":"order","customer":{"id":"c-1"}}' $B/echo)
expect_contains "header_down placeholder" "$r1h" "X-Served-By: 127.0.0.1:911"
r2=$(curl -s -X POST -d '{"type":"refund"}' $B/echo)
expect_contains "json route value list OR" "$r2" '"name": "orders'
r3=$(curl -s -X POST -d '{"type":"other"}' $B/echo)
expect_contains "json non-match falls through" "$r3" '"name": "'
case "$r3" in *orders*) fail "json non-match avoids orders pool";; *) ok "json non-match avoids orders pool";; esac
r4=$(curl -s -X GET -d '{"type":"order"}' $B/echo)
case "$r4" in *orders*) fail "method matcher ANDed";; *) ok "method matcher ANDed";; esac
r5=$(curl -s -X PUT -d '{"amount": 1500.5, "note":"x"}' $B/echo)
expect_contains "json numeric comparison" "$r5" '"X-Route": "vip"'
r6=$(curl -s -X PUT -d '{"amount": 999}' $B/echo)
case "$r6" in *'"X-Route": "vip"'*) fail "json numeric below threshold";; *) ok "json numeric below threshold";; esac
r7=$(curl -s -X POST -d 'item=1&action=checkout' $B/echo)
expect_contains "form matcher" "$r7" '"name": "c"'
r8=$(curl -s -X POST -d 'priority=urgent&x=1' $B/echo)
expect_contains "body regex matcher" "$r8" '"name": "c"'
r9=$(curl -s -H 'X-Tenant: acme' $B/echo)
expect_contains "header matcher" "$r9" '"name": "b"'
r10=$(curl -s -X POST -d '{"type":"order","amount":5000}' $B/echo)
expect_contains "first matching route wins" "$r10" '"name": "orders'
r11=$(curl -s -X POST -d '{"type":"order", "customer":{"id":"cé-\"q\""}}' $B/echo)
expect_contains "json with escapes still routes" "$r11" '"name": "orders'
r12=$(curl -s -X POST -d '{"type":' $B/echo)
expect_contains "malformed json falls through" "$r12" '"name": "'

echo "# payload hashing is sticky"
sticky_ok=1
for cust in c-1 c-2 c-3 c-4 c-5 c-6; do
    first=$(curl -s -X POST -d "{\"type\":\"order\",\"customer\":{\"id\":\"$cust\"}}" $B/echo | python3 -c 'import sys,json;print(json.load(sys.stdin)["name"])')
    for i in 1 2 3; do
        n=$(curl -s -X POST -d "{\"type\":\"order\",\"customer\":{\"id\":\"$cust\"}}" $B/echo | python3 -c 'import sys,json;print(json.load(sys.stdin)["name"])')
        [ "$n" = "$first" ] || sticky_ok=0
    done
done
check "same json key always hits the same upstream" $((1-sticky_ok))
dist=$(for cust in $(seq 1 40); do curl -s -X POST -d "{\"type\":\"order\",\"customer\":{\"id\":\"cust-$cust\"}}" $B/echo | python3 -c 'import sys,json;print(json.load(sys.stdin)["name"])'; done | sort | uniq -c | wc -l)
expect_eq "hash spreads keys over both upstreams" "$dist" "2"

hs_ok=1
for s in s1 s2 s3 s4 s5; do
    first=$(curl -s -H "X-Session: $s" $B/sticky/x)
    for i in 1 2; do [ "$(curl -s -H "X-Session: $s" $B/sticky/x)" = "$first" ] || hs_ok=0; done
done
check "header hash is sticky" $((1-hs_ok))
dist=$(for s in $(seq 1 30); do echo "$(curl -s -H "X-Session: sess-$s" $B/sticky/x)"; done | sort -u | wc -l)
expect_eq "header hash uses all three upstreams" "$dist" "3"
cs_ok=1
for s in k1 k2 k3 k4; do
    first=$(curl -s -b "a=1; sid=$s; z=9" $B/cookie)
    for i in 1 2; do [ "$(curl -s -b "sid=$s" $B/cookie)" = "$first" ] || cs_ok=0; done
done
check "cookie hash is sticky" $((1-cs_ok))

echo "# weights"
counts=$(for i in $(seq 1 40); do echo "$(curl -s $B/weighted)"; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')
expect_contains "weighted rr: a gets 3/4" "$counts" "30 hello from a"
expect_contains "weighted rr: b gets 1/4" "$counts" "10 hello from b"

echo "# bodies and framing"
big=$(head -c 300000 /dev/urandom | base64 -w0)
echo -n "$big" > "$TMP/big.txt"
r=$(curl -s -X POST --data-binary "@$TMP/big.txt" $B/echo | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["body_len"], d["body"]==open("tests/tmp/big.txt").read())')
expect_eq "large request body forwarded intact" "$r" "$(stat -c %s $TMP/big.txt) True"
r=$(curl -s -X POST -H 'Transfer-Encoding: chunked' --data-binary "@$TMP/big.txt" $B/echo | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["body_len"], d["body"]==open("tests/tmp/big.txt").read(), d["headers"].get("Transfer-Encoding","none"))')
expect_eq "chunked request body is decoded and forwarded with Content-Length" "$r" "$(stat -c %s $TMP/big.txt) True none"
r=$(curl -s -X POST -H 'Expect: 100-continue' --data-binary "@$TMP/big.txt" $B/echo | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["body_len"])')
expect_eq "expect 100-continue" "$r" "$(stat -c %s $TMP/big.txt)"
expect_eq "chunked response passthrough" "$(curl -s $B/chunked)" "alpha-beta-gamma"
expect_contains "chunked response keeps TE header" "$(curl -s -D - -o /dev/null $B/chunked)" "Transfer-Encoding: chunked"
expect_eq "chunked response for HTTP/1.0 client is dechunked" "$(curl -s --http1.0 $B/chunked)" "alpha-beta-gamma"
expect_contains "close-delimited response" "$(curl -s $B/nolength)" "close-delimited body from"
sz=$(curl -s $B/big | wc -c)
expect_eq "3 MiB response streamed" "$sz" "3145728"
sum1=$(curl -s $B/big | md5sum | cut -d' ' -f1); sum2=$(curl -s http://127.0.0.1:9101/big | md5sum | cut -d' ' -f1)
expect_eq "large response intact" "$sum1" "$sum2"
head_out=$(curl -s -I $B/big)
expect_contains "HEAD passes Content-Length" "$head_out" "Content-Length: 3145728"
expect_eq "HEAD then GET on same connection" "$(curl -s -I $B/ping -o /dev/null -w '%{http_code} ' ; curl -s $B/ping)" "200 pong"
expect_eq "413 for oversized body" "$(H -X POST -H 'Content-Length: 2000000' -d 'x' $B/echo)" "413"
expect_eq "204 response has no body" "$(curl -s -D - $B/status/204 | tail -c 2 | od -An -c | tr -d ' ')" '\r\n'
expect_eq "5xx from upstream passed through" "$(H $B/status/500)" "500"

echo "# keep-alive and pipelining"
r=$(curl -s -o /dev/null -o /dev/null -o /dev/null $B/ping $B/ping $B/ping -w '%{num_connects} ')
expect_eq "client keep-alive reuses connection" "$r" "1 0 0 "
r=$(curl -s -o /dev/null -o /dev/null $B/echo $B/echo -w '%{num_connects} ')
expect_eq "proxied keep-alive reuses connection" "$r" "1 0 "
pipe=$(printf 'GET /ping HTTP/1.1\r\nHost: x\r\n\r\nGET /ping HTTP/1.1\r\nHost: x\r\n\r\nGET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' | timeout 3 python3 -c '
import socket,sys
s=socket.create_connection(("127.0.0.1",9180)); s.sendall(sys.stdin.buffer.read()); d=b""
while True:
    b=s.recv(65536)
    if not b: break
    d+=b
print(d.count(b"pong"), d.count(b"HTTP/1.1 200"))')
expect_eq "pipelined requests" "$pipe" "3 3"
pipe=$(printf 'POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET /echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' | timeout 3 python3 -c '
import socket,sys
s=socket.create_connection(("127.0.0.1",9180)); s.sendall(sys.stdin.buffer.read()); d=b""
while True:
    b=s.recv(65536)
    if not b: break
    d+=b
print(d.count(b"HTTP/1.1 200"), b"\"body\": \"hello\"" in d)')
expect_eq "pipelined proxied requests" "$pipe" "2 True"
r=$(curl -s -o /dev/null -w '%{http_code}' --http1.0 $B/ping)
expect_eq "HTTP/1.0 request" "$r" "200"

echo "# errors, timeouts, retries, health"
r=$(timeout 3 python3 -c '
import socket
s = socket.create_connection(("127.0.0.1", 9180))
s.sendall(b"GARBAGE\r\n\r\n")
print(s.makefile("rb").readline().decode().strip())' 2>/dev/null)
expect_eq "malformed request gets 400" "$r" "HTTP/1.1 400 Bad Request"
expect_eq "no route -> 404" "$(H http://127.0.0.1:9184/other)" "404"
expect_eq "route-only server matches" "$(curl -s http://127.0.0.1:9184/only)" "only"
expect_eq "unreachable upstreams -> 502" "$(H $B/dead)" "502"
expect_eq "first policy fails over to live upstream" "$(curl -s $B/failover)" "hello from a"
expect_eq "response timeout -> 504" "$(H $B/slow)" "504"
expect_eq "upstream drops connection -> 502" "$(H $B/drop)" "502"
expect_eq "health check steers away from sick upstream" "$(curl -s $B/sick)" "hello from a"
r=$(printf 'GET /ping HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc' | timeout 5 python3 -c '
import socket,sys,time
s=socket.create_connection(("127.0.0.1",9180)); s.sendall(sys.stdin.buffer.read()); s.settimeout(4)
try:
    d=s.recv(65536)
except Exception as e:
    d=str(e).encode()
print(d.split(b"\r\n")[0].decode())')
expect_eq "slow client body -> 408" "$r" "HTTP/1.1 408 Request Timeout"
r=$(printf 'GET /ping HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | timeout 3 python3 -c '
import socket,sys
s=socket.create_connection(("127.0.0.1",9180)); s.sendall(sys.stdin.buffer.read()); print(s.recv(65536).split(b"\r\n")[0].decode())')
expect_eq "CL + TE together is rejected" "$r" "HTTP/1.1 400 Bad Request"

echo "# least_conn"
# hold 4 slow connections? we lack a hold endpoint on a/b; just verify it distributes
dist=$(for i in $(seq 1 10); do echo "$(curl -s $B/least)"; done | sort -u | wc -l)
expect_eq "least_conn uses both upstreams" "$dist" "2"

echo "# websocket-style upgrade"
ws=$(timeout 5 python3 - <<'PY'
import socket
s=socket.create_connection(("127.0.0.1",9180))
s.sendall(b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\n\r\n")
d=b""
while b"\r\n\r\n" not in d:
    d+=s.recv(4096)
head,rest=d.split(b"\r\n\r\n",1)
s.sendall(b"ping-1")
rest+=s.recv(4096)
s.sendall(b"ping-2")
while b"ping-2" not in rest:
    rest+=s.recv(4096)
print(head.split(b"\r\n")[0].decode(), b"Upgrade: websocket" in head, rest.decode())
PY
)
expect_eq "101 upgrade tunnels bytes both ways" "$ws" "HTTP/1.1 101 Switching Protocols True echo:ping-1echo:ping-2"

echo "# admin api"
A="http://127.0.0.1:9199"
expect_contains "admin /health" "$(curl -s $A/health)" '"status":"ok"'
ups=$(curl -s $A/upstreams)
expect_contains "admin /upstreams lists pools" "$ups" '"name":"orders"'
expect_contains "admin /upstreams shows hash key" "$ups" '"hash_key":{"source":"json","name":"customer.id"}'
expect_contains "admin /upstreams marks sick upstream" "$ups" '"address":"127.0.0.1:9131","weight":1,"drained":false,"healthy":false'
expect_contains "admin /metrics" "$(curl -s $A/metrics)" 'limer_upstream_healthy{worker="0",pool="sick",upstream="127.0.0.1:9131"} 0'
expect_contains "admin /config" "$(curl -s $A/config)" "route orders"
expect_eq "admin unknown -> 404" "$(H $A/nope)" "404"

echo "# second server block"
expect_eq "second listener works" "$(curl -s http://127.0.0.1:9181/)" "hello from a"

echo "# reload"
sed -i 's/respond 200 "pong"/respond 200 "pong2"/; s/127.0.0.1:9181 {/127.0.0.1:9181, 127.0.0.1:9182 {/' "$TMP/Limerfile"
$BIN reload -c "$TMP/Limerfile" >/dev/null 2>&1 || kill -HUP $LIMER
sleep 0.6
expect_eq "reload changes respond body" "$(curl -s $B/ping)" "pong2"
expect_eq "reload adds listener" "$(curl -s http://127.0.0.1:9182/)" "hello from a"
expect_eq "reload keeps old listener" "$(curl -s http://127.0.0.1:9181/)" "hello from a"
printf 'this is not valid {\n' > "$TMP/Limerfile.bad"
cp "$TMP/Limerfile" "$TMP/Limerfile.good"; cp "$TMP/Limerfile.bad" "$TMP/Limerfile"
kill -HUP $LIMER; sleep 0.5
expect_eq "bad reload keeps running config" "$(curl -s $B/ping)" "pong2"
cp "$TMP/Limerfile.good" "$TMP/Limerfile"

echo "# concurrency"
conc=$(python3 - <<'PY'
import socket, threading, json
ok=0; lock=threading.Lock()
def worker(i):
    global ok
    try:
        s=socket.create_connection(("127.0.0.1",9180)); s.settimeout(10)
        body=json.dumps({"type":"order","customer":{"id":"cc-%d"%i}}).encode()
        for k in range(5):
            s.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
            d=b""
            while b"\r\n\r\n" not in d: d+=s.recv(65536)
            head,rest=d.split(b"\r\n\r\n",1)
            n=int([l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0].split(b":")[1])
            while len(rest)<n: rest+=s.recv(65536)
            if b'"name": "orders' in rest:
                with lock: ok+=1
        s.close()
    except Exception as e:
        pass
ts=[threading.Thread(target=worker,args=(i,)) for i in range(50)]
[t.start() for t in ts]; [t.join() for t in ts]
print(ok)
PY
)
expect_eq "50 concurrent keep-alive clients x5 requests" "$conc" "250"

echo "# access log"
expect_contains "access log line" "$(head -1 $TMP/access.log)" 'route='

echo "# graceful stop"
$BIN stop -c "$TMP/Limerfile" >/dev/null 2>&1 || kill -TERM $LIMER
for _ in $(seq 1 50); do kill -0 $LIMER 2>/dev/null || break; sleep 0.1; done
if kill -0 $LIMER 2>/dev/null; then fail "limer stops on SIGTERM"; else ok "limer stops on SIGTERM"; fi
check "pidfile removed" $([ ! -e "$TMP/limer.pid" ] && echo 0 || echo 1)

echo "# tls termination"
if $BIN version | grep -q tls && command -v openssl >/dev/null; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 1 -subj "/CN=localhost" >/dev/null 2>&1
    printf '{\n  log_level warn\n}\nhttps://127.0.0.1:9185 {\n  tls tests/tmp/cert.pem tests/tmp/key.pem\n  route {\n    match json type order\n    to 127.0.0.1:9111\n  }\n  reverse_proxy 127.0.0.1:9101\n}\n' > "$TMP/tls.conf"
    $BIN run -c "$TMP/tls.conf" >/dev/null 2>"$TMP/tls.log" &
    TLSP=$!; PIDS+=($TLSP)
    for _ in $(seq 1 50); do curl -sk -o /dev/null https://127.0.0.1:9185/ 2>/dev/null && break; sleep 0.1; done
    expect_eq "https request proxied" "$(curl -sk https://127.0.0.1:9185/)" "hello from a"
    expect_contains "https sets X-Forwarded-Proto" "$(curl -sk https://127.0.0.1:9185/echo)" '"X-Forwarded-Proto": "https"'
    expect_contains "https payload routing" "$(curl -sk -X POST -d '{"type":"order"}' https://127.0.0.1:9185/echo)" '"name": "orders1"'
    r=$(curl -sk -o /dev/null -o /dev/null https://127.0.0.1:9185/ping https://127.0.0.1:9185/ -w '%{num_connects} ')
    expect_eq "https keep-alive" "$r" "1 0 "
    sum=$(curl -sk https://127.0.0.1:9185/big | md5sum | cut -d' ' -f1)
    expect_eq "https large response intact" "$sum" "$(curl -s http://127.0.0.1:9101/big | md5sum | cut -d' ' -f1)"
    r=$(curl -sk -X POST --data-binary "@$TMP/big.txt" https://127.0.0.1:9185/echo | python3 -c 'import sys,json;print(json.load(sys.stdin)["body_len"])')
    expect_eq "https large request body" "$r" "$(stat -c %s $TMP/big.txt)"
    expect_eq "plain http on tls port is rejected" "$(H http://127.0.0.1:9185/ 2>/dev/null)" "000"
    kill -TERM $TLSP; wait $TLSP 2>/dev/null
else
    echo "  skip - TLS not available in this build"
fi

echo "# multi-worker mode"
printf '{\n  workers 2\n  log_level warn\n}\n127.0.0.1:9183 {\n  reverse_proxy 127.0.0.1:9101 127.0.0.1:9102\n}\n' > "$TMP/mw.conf"
$BIN run -c "$TMP/mw.conf" >/dev/null 2>"$TMP/mw.log" &
MW=$!; PIDS+=($MW)
wait_port 9183 || fail "multi-worker start"
names=$(for i in $(seq 1 12); do echo "$(curl -s http://127.0.0.1:9183/)"; done | sort -u | tr '\n' ' ')
expect_eq "multi-worker serves requests" "$names" "hello from a hello from b "
kill -TERM $MW; for _ in $(seq 1 50); do kill -0 $MW 2>/dev/null || break; sleep 0.1; done
if kill -0 $MW 2>/dev/null; then fail "master stops workers"; else ok "master stops workers"; fi

if grep -q "Sanitizer\|runtime error" "$TMP/limer.log" "$TMP/mw.log" "$TMP/tls.log" 2>/dev/null; then
    fail "no sanitizer reports in proxy logs" "$(grep -h "Sanitizer\|runtime error" "$TMP"/*.log | head -3)"
else
    ok "no sanitizer reports in proxy logs"
fi
if grep -qi "error\|warn" "$TMP/limer.log"; then
    echo "# notable log lines:"; grep -i "error\|warn" "$TMP/limer.log" | head -20
fi

echo
echo "passed: $PASS  failed: $FAIL"
[ $FAIL -eq 0 ]
