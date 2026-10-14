#!/usr/bin/env bash
#
# compare.sh - limer vs nginx vs HAProxy: same backends, same load, same box.
#
#   ./bench/compare.sh [duration] [connections] [rounds]
#
# Each proxy gets one worker process / thread, keep-alive to the backends and
# no access logging, and round-robins over two copies of bench/backend.c. Only
# loopback test ports are used (18080-18082, 19001-19002); nginx and haproxy
# run from private configs in a temp dir and are killed on exit, so their
# system services are never started or touched. Needs wrk, nginx and haproxy.
# Every scenario runs `rounds` times per proxy (default 2) in rotating order and
# the best run is reported, to damp noise from a shared or small machine.
set -u
cd "$(dirname "$0")/.."
DUR=${1:-10s}
CONNS=${2:-100}
ROUNDS=${3:-2}
for t in wrk nginx haproxy cc; do
    command -v "$t" >/dev/null || { echo "$t is required"; exit 1; }
done
ulimit -n 65536 2>/dev/null || true
make -s || exit 1
cc -O2 -o bench/backend bench/backend.c || exit 1

TMP=$(mktemp -d)
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    [ -f "$TMP/nginx.pid" ] && kill "$(cat "$TMP/nginx.pid")" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

./bench/backend 19001 & PIDS+=($!)
./bench/backend 19002 & PIDS+=($!)

cat > "$TMP/Limerfile" <<EOF
{
    admin off
    log_level warn
    workers 1
}
127.0.0.1:18080 {
    reverse_proxy 127.0.0.1:19001 127.0.0.1:19002
}
EOF
./limer run -c "$TMP/Limerfile" & PIDS+=($!)

mkdir -p "$TMP/ngx"
cat > "$TMP/nginx.conf" <<EOF
worker_processes 1;
daemon off;
pid $TMP/nginx.pid;
error_log $TMP/nginx.err warn;
events { worker_connections 20000; }
http {
    access_log off;
    client_body_temp_path $TMP/ngx; proxy_temp_path $TMP/ngx; fastcgi_temp_path $TMP/ngx;
    uwsgi_temp_path $TMP/ngx; scgi_temp_path $TMP/ngx;
    upstream be {
        server 127.0.0.1:19001;
        server 127.0.0.1:19002;
        keepalive 256;
    }
    server {
        listen 127.0.0.1:18081;
        location / {
            proxy_pass http://be;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
    }
}
EOF
nginx -e "$TMP/nginx.err" -p "$TMP" -c "$TMP/nginx.conf" & PIDS+=($!)

cat > "$TMP/haproxy.cfg" <<EOF
global
    nbthread 1
    maxconn 20000
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    option http-keep-alive
    http-reuse always
frontend fe
    bind 127.0.0.1:18082
    default_backend be
backend be
    balance roundrobin
    server a 127.0.0.1:19001
    server b 127.0.0.1:19002
EOF
haproxy -f "$TMP/haproxy.cfg" -db & PIDS+=($!)
sleep 1

for p in 18080 18081 18082; do
    curl -fs -o /dev/null "http://127.0.0.1:$p/" || { echo "proxy on :$p is not answering"; exit 1; }
done

echo "# $(uname -sr), $(nproc) CPU(s); wrk -t2 -d$DUR; best of $ROUNDS"
echo "# limer $(./limer version | cut -d' ' -f2) | $(nginx -v 2>&1 | sed 's/.*: //') | $(haproxy -v | head -1 | cut -d' ' -f1-3)"

# one wrk run -> "req/s p50 p99"
measure() { # url conns [wrk args...]
    local url=$1 c=$2
    shift 2
    wrk -t2 -c"$c" -d"$DUR" --latency "$@" "$url" 2>/dev/null |
        awk '/Requests\/sec/{r=$2} /^ +50%/{p50=$2} /^ +99%/{p99=$2} END{printf "%s %s %s", r, p50, p99}'
}

scenario() { # label conns [wrk args...]
    local label=$1 c=$2
    shift 2
    printf "\n## %s\n" "$label"
    printf "%-9s %12s %10s %10s\n" proxy "req/s" p50 p99
    declare -A best
    local names=(limer nginx haproxy) ports=(18080 18081 18082)
    for ((r = 0; r < ROUNDS; r++)); do
        for ((k = 0; k < 3; k++)); do
            local i=$(( (k + r) % 3 ))
            local out
            out=$(measure "http://127.0.0.1:${ports[$i]}/" "$c" "$@")
            local rps=${out%% *}
            local prev=${best[${names[$i]}]:-0 - -}
            if awk -v a="$rps" -v b="${prev%% *}" 'BEGIN{exit !(a > b)}'; then
                best[${names[$i]}]=$out
            fi
        done
    done
    for n in "${names[@]}"; do
        read -r rps p50 p99 <<<"${best[$n]}"
        printf "%-9s %12s %10s %10s\n" "$n" "$rps" "$p50" "$p99"
    done
}

scenario "GET, keep-alive, $CONNS connections" "$CONNS"
scenario "GET, keep-alive, 1000 connections" 1000
scenario "POST 120 B JSON, keep-alive, $CONNS connections" "$CONNS" -s bench/post.lua
scenario "GET, new connection per request, $CONNS connections" "$CONNS" -H "Connection: close"
