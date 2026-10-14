#!/usr/bin/env bash
#
# protocols.sh - HTTP/1.1 over TLS vs HTTP/2 vs HTTP/3 through limer, same box.
#
#   ./bench/protocols.sh [requests] [rounds]
#
# One limer worker with a `tls internal` site on 127.0.0.1:18443 (TCP and UDP)
# round-robins over two copies of bench/backend.c (19001-19002). h2load drives
# it over each protocol with the same number of connections and requests in
# flight, and the best of `rounds` runs (default 3) is reported. HTTP/3 needs an
# h2load built with --enable-http3; point H2LOAD at it if it is not on PATH.
set -u
cd "$(dirname "$0")/.."
N=${1:-100000}
ROUNDS=${2:-3}
H2LOAD=${H2LOAD:-h2load}
command -v "$H2LOAD" >/dev/null || { echo "h2load is required (set H2LOAD)"; exit 1; }
ulimit -n 65536 2>/dev/null || true
make -s || exit 1
./limer version | grep -q 'http/3' || { echo "this limer has no HTTP/3 support"; exit 1; }
cc -O2 -o bench/backend bench/backend.c || exit 1

TMP=$(mktemp -d)
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

./bench/backend 19001 & PIDS+=($!)
./bench/backend 19002 & PIDS+=($!)

cat > "$TMP/Limerfile" <<EOF
{
    admin off
    log_level error
    workers 1
    http3
    storage $TMP/storage
}
https://127.0.0.1:18443 {
    tls internal
    reverse_proxy 127.0.0.1:19001 127.0.0.1:19002
}
EOF
./limer run -c "$TMP/Limerfile" 2>"$TMP/limer.log" & PIDS+=($!)
sleep 1

# best requests/s of $ROUNDS runs, plus that run's latency percentiles
best() {
    local top=0 line out lat= ok=
    for _ in $(seq "$ROUNDS"); do
        out=$("$H2LOAD" "$@" https://127.0.0.1:18443/ 2>&1)
        line=$(awk '/finished in/{print $4}' <<<"$out" | tr -d ,)
        if [ -z "$line" ]; then
            echo "h2load failed:" >&2; tail -5 <<<"$out" >&2; return
        fi
        if awk -v a="$line" -v b="$top" 'BEGIN{exit !(a > b)}'; then
            top=$line
            # h2load 1.70+: "request : min max median p95 p99 mean ..."
            lat=$(awk '/^request +:/{print "p50 " $5 "  p99 " $7}' <<<"$out")
            ok=$(awk '/^requests:/{print $8, "ok,", $10, "failed"}' <<<"$out")
        fi
    done
    printf "%10.0f req/s   %-24s %s\n" "$top" "$lat" "$ok"
}

echo "# h2load -> limer (1 worker, TLS) -> backends, $N requests, best of $ROUNDS"
for shape in "10 1" "10 10" "100 1"; do
    set -- $shape
    c=$1 m=$2
    echo "## $c connections x $m in flight"
    printf "%-22s " "HTTP/1.1 over TLS"
    if [ "$m" = 1 ]; then best -n "$N" -c "$c" --h1; else echo "(HTTP/1.1 has no multiplexing)"; fi
    printf "%-22s " "HTTP/2"; best -n "$N" -c "$c" -m "$m" --alpn-list=h2
    printf "%-22s " "HTTP/3"; best -n "$N" -c "$c" -m "$m" --alpn-list=h3
done
grep -E 'ERROR|AddressSanitizer' "$TMP/limer.log" | head -5
