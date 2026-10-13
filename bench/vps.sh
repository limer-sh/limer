#!/usr/bin/env bash
#
# vps.sh - build Limer on a VPS and benchmark it against a local C backend.
#
# Safe to run on a box that also runs something else: it binds only loopback
# test ports (18080 plain, 18443 TLS, 19001/19002 backends), never 80/443,
# starts nothing on boot, and kills everything it started on exit. It does
# not touch an existing Caddy, nginx, systemd unit or firewall.
#
#   ./bench/vps.sh [duration] [connections]
#
# Run it from a checkout of the limer repo on the VPS:
#   git clone https://github.com/restimguay/limer && cd limer
#   git checkout claude/http-load-balancer-payload-mq972p
#   ./bench/vps.sh
#
# Needs a C compiler, wrk and pkg-config; installs them with apt-get when
# missing and run as root. OpenSSL / nghttp2 / zlib dev headers enable the
# TLS, HTTP/2 and compression tests (optional).
set -u
cd "$(dirname "$0")/.."

DUR=${1:-10s}
CONNS=${2:-200}
PLAIN=18080
TLS=18443
B1=19001
B2=19002

say() { printf '\n== %s ==\n' "$*"; }

# ---- dependencies -------------------------------------------------------
need_apt=()
command -v cc >/dev/null || command -v gcc >/dev/null || need_apt+=(build-essential)
command -v pkg-config >/dev/null || need_apt+=(pkg-config)
command -v wrk >/dev/null || need_apt+=(wrk)
# optional dev headers (the Makefile auto-detects them)
pkg-config --exists openssl 2>/dev/null   || need_apt+=(libssl-dev)
pkg-config --exists libnghttp2 2>/dev/null || need_apt+=(libnghttp2-dev)
pkg-config --exists zlib 2>/dev/null       || need_apt+=(zlib1g-dev)
if [ "${#need_apt[@]}" -gt 0 ]; then
    if [ "$(id -u)" = 0 ] && command -v apt-get >/dev/null; then
        say "installing: ${need_apt[*]}"
        apt-get update -qq && apt-get install -y -qq "${need_apt[@]}" || true
    else
        echo "missing tools: ${need_apt[*]} (install them, or run as root on Debian/Ubuntu)"
    fi
fi
command -v wrk >/dev/null || { echo "wrk is required and could not be installed; aborting"; exit 1; }

WORKERS=$(nproc)
say "host: $(nproc) cores, $(command -v cc >/dev/null && cc --version 2>/dev/null | head -1)"

# ---- build --------------------------------------------------------------
say "building limer"
make -s || { echo "build failed"; exit 1; }
./limer version
cc -O2 -o bench/backend bench/backend.c || { echo "backend build failed"; exit 1; }

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -f bench/vps.conf bench/vps-tls.conf bench/vps-cache.conf; }
trap cleanup EXIT

./bench/backend "$B1" & PIDS+=($!)
./bench/backend "$B2" & PIDS+=($!)
sleep 0.3

run() { # label url [extra wrk args...]
    local label=$1 url=$2; shift 2
    local out
    out=$(wrk -t"$WORKERS" -c"$CONNS" -d"$DUR" --latency "$@" "$url" 2>&1)
    printf "%-40s %12s req/s   p50 %-9s p99 %-9s %s\n" "$label" \
        "$(awk '/Requests\/sec/{print $2}' <<<"$out")" \
        "$(awk '/ 50%/{print $2}' <<<"$out")" \
        "$(awk '/ 99%/{print $2}' <<<"$out")" \
        "$(grep -oE 'Non-2xx[^ ]* [0-9]+|Socket errors.*' <<<"$out" | tr '\n' ' ')"
}

# ---- baseline: wrk straight to the backend (the ceiling) ----------------
say "baseline: wrk -> backend directly ($CONNS conns, $DUR, $WORKERS threads)"
run "direct GET" "http://127.0.0.1:$B1/"

# ---- plain HTTP proxy ---------------------------------------------------
cat > bench/vps.conf <<CFG
{
    log_level warn
    admin off
    workers auto
}
127.0.0.1:$PLAIN {
    route orders {
        match method POST
        match json type order
        to 127.0.0.1:$B1 127.0.0.1:$B2
        lb_policy hash json customer.id
    }
    reverse_proxy 127.0.0.1:$B1 127.0.0.1:$B2
}
CFG
say "limer plain HTTP, workers auto ($WORKERS) -> 2 backends"
./limer run -c bench/vps.conf 2>/dev/null & LP=$!; PIDS+=($LP)
sleep 0.6
run "GET, round robin" "http://127.0.0.1:$PLAIN/"
run "POST json match + payload hash" "http://127.0.0.1:$PLAIN/" -s bench/post.lua
run "GET, 1000 connections" "http://127.0.0.1:$PLAIN/" -c1000
kill -TERM $LP 2>/dev/null; wait $LP 2>/dev/null

# ---- response cache (served from memory, no upstream) -------------------
# The bench backend sends no Cache-Control, so a config ttl makes it cacheable.
cat > bench/vps-cache.conf <<CFG
{
    log_level warn
    admin off
    workers auto
}
127.0.0.1:$PLAIN {
    cache {
        ttl 60s
    }
    reverse_proxy 127.0.0.1:$B1
}
CFG
say "limer response cache (hits served from memory)"
./limer run -c bench/vps-cache.conf 2>/dev/null & LP=$!; PIDS+=($LP)
sleep 0.6
curl -s -o /dev/null "http://127.0.0.1:$PLAIN/"   # prime one entry
run "GET, cache hit" "http://127.0.0.1:$PLAIN/"
kill -TERM $LP 2>/dev/null; wait $LP 2>/dev/null

# ---- TLS / HTTP/2 (if this build has TLS) -------------------------------
if ./limer version | grep -q tls; then
    cat > bench/vps-tls.conf <<CFG
{
    log_level warn
    admin off
    workers auto
}
https://localhost:$TLS {
    tls internal
    reverse_proxy 127.0.0.1:$B1 127.0.0.1:$B2
}
CFG
    say "limer HTTPS, workers auto -> 2 backends"
    ./limer run -c bench/vps-tls.conf 2>/dev/null & LP=$!; PIDS+=($LP)
    sleep 0.8
    if command -v h2load >/dev/null; then
        printf "%-40s " "HTTP/2 (10 conns x 10 streams)"
        h2load -n 200000 -c 10 -m 10 "https://localhost:$TLS/" 2>&1 | awk '/finished in/{print $4,$5}'
        printf "%-40s " "HTTP/1.1 over TLS (100 conns)"
        h2load -n 200000 -c 100 --h1 "https://localhost:$TLS/" 2>&1 | awk '/finished in/{print $4,$5}'
    else
        run "HTTPS GET (wrk, HTTP/1.1)" "https://localhost:$TLS/"
        echo "  (install h2load for an HTTP/2 figure)"
    fi
    kill -TERM $LP 2>/dev/null; wait $LP 2>/dev/null
else
    say "this build has no TLS (install libssl-dev and rebuild for the HTTPS test)"
fi

say "done"
