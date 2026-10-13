#!/usr/bin/env bash
# Reproducible throughput/latency benchmark for Limer.
# Requires wrk (https://github.com/wg/wrk) and a C compiler.
#   ./bench/run.sh [duration] [connections]
set -u
cd "$(dirname "$0")/.."
DUR=${1:-8s}
CONNS=${2:-100}
command -v wrk >/dev/null || { echo "wrk is required"; exit 1; }
make -s || exit 1
cc -O2 -o bench/backend bench/backend.c || exit 1
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null' EXIT
./bench/backend 9001 & PIDS+=($!)
./bench/backend 9002 & PIDS+=($!)
sleep 0.3

run() { # label url [wrk args...]
    local label=$1 url=$2; shift 2
    local out
    out=$(wrk -t2 -c"$CONNS" -d"$DUR" --latency "$@" "$url" 2>&1)
    printf "%-38s %10s req/s   p50 %-9s p99 %-9s %s\n" "$label" \
        "$(awk '/Requests\/sec/{print $2}' <<<"$out")" \
        "$(awk '/ 50%/{print $2}' <<<"$out")" \
        "$(awk '/ 99%/{print $2}' <<<"$out")" \
        "$(grep -o 'Non-2xx.*\|Socket errors.*' <<<"$out" | tr '\n' ' ')"
}

echo "# wrk -> backend directly (baseline, $CONNS connections, $DUR)"
run "direct GET" http://127.0.0.1:9001/
run "direct POST (120 B JSON)" http://127.0.0.1:9001/ -s bench/post.lua

if command -v caddy >/dev/null; then
    for c in 1 "$(nproc)"; do
        echo "# wrk -> caddy $(caddy version | cut -d' ' -f1) (GOMAXPROCS=$c) -> backends, same backends and settings"
        GOMAXPROCS=$c caddy run --config bench/Caddyfile --adapter caddyfile >/dev/null 2>&1 & CP=$!
        sleep 1
        run "caddy GET, round robin" http://127.0.0.1:8081/
        run "caddy POST (120 B JSON, no inspection)" http://127.0.0.1:8081/ -s bench/post.lua
        run "caddy GET, 1000 connections" http://127.0.0.1:8081/ -c1000
        kill $CP; wait $CP 2>/dev/null
    done
fi

if command -v h2load >/dev/null; then
    cat > bench/Limerfile.h2 <<'CFG'
{
    log_level warn
    admin off
}
https://localhost:8443 {
    tls internal
    reverse_proxy 127.0.0.1:9001 127.0.0.1:9002
}
CFG
    for w in 1 "$(nproc)"; do
        echo "# h2load -> limer ($w worker(s), TLS) -> backends"
        ./limer run -c bench/Limerfile.h2 -w "$w" 2>/dev/null & LP=$!
        sleep 0.6
        printf "%-38s " "HTTP/2, 10 conns x 10 streams"; h2load -n 100000 -c 10 -m 10 https://localhost:8443/ 2>&1 | awk '/finished in/{print $4, $5}'
        printf "%-38s " "HTTP/1.1 over TLS, 10 conns"; h2load -n 100000 -c 10 --h1 https://localhost:8443/ 2>&1 | awk '/finished in/{print $4, $5}'
        kill -TERM $LP; wait $LP 2>/dev/null
    done
    rm -f bench/Limerfile.h2
fi

for w in 1 "$(nproc)"; do
    echo "# wrk -> limer ($w worker(s)) -> backends"
    ./limer run -c bench/Limerfile -w "$w" 2>/dev/null & LP=$!
    sleep 0.5
    run "GET, round robin" http://127.0.0.1:8080/
    run "POST, json match + payload hash" http://127.0.0.1:8080/ -s bench/post.lua
    run "GET, 1000 connections" http://127.0.0.1:8080/ -c1000
    kill -TERM $LP; wait $LP 2>/dev/null
done
