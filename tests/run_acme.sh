#!/usr/bin/env bash
# Automatic HTTPS test against the Pebble ACME test server.
# Requires a `pebble` binary (https://github.com/letsencrypt/pebble) on PATH
# or in $PEBBLE, and resolvable test names (127.0.0.1 limer.test www.limer.test
# in /etc/hosts).
set -u
cd "$(dirname "$0")/.."
export no_proxy='*' NO_PROXY='*'
PEBBLE=${PEBBLE:-$(command -v pebble || true)}
if [ -z "$PEBBLE" ] || ! getent hosts limer.test >/dev/null; then
    echo "  skip - pebble not available or limer.test does not resolve"
    exit 0
fi
TMP=tests/tmp/acme
rm -rf "$TMP"; mkdir -p "$TMP/storage"
PASS=0; FAIL=0; PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
ok()   { PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL - $1"; [ -n "${2:-}" ] && echo "         ${2:0:400}"; }
expect_contains() { case "$2" in *"$3"*) ok "$1";; *) fail "$1" "missing '$3' in: ${2:0:300}";; esac; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }
wait_port() { for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.1; done; return 1; }

make -s || exit 1
# Pebble's own HTTPS certificate (self-signed, trusted via acme_ca_root)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$TMP/pebble.key" \
    -out "$TMP/pebble.crt" -days 2 -subj "/CN=pebble" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
cat > "$TMP/pebble.json" <<CFG
{ "pebble": {
    "listenAddress": "127.0.0.1:14000",
    "managementListenAddress": "127.0.0.1:15000",
    "certificate": "$TMP/pebble.crt",
    "privateKey": "$TMP/pebble.key",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
} }
CFG
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=${NONCEREJECT:-0} "$PEBBLE" -config "$TMP/pebble.json" -strict >"$TMP/pebble.log" 2>&1 &
PIDS+=($!)
wait_port 14000 || { echo "pebble did not start"; cat "$TMP/pebble.log"; exit 1; }
python3 tests/backend.py 9801 acme-backend & PIDS+=($!)
wait_port 9801

cat > "$TMP/Limerfile" <<CFG
{
    http_port 5002
    https_port 5443
    storage $TMP/storage
    acme_ca https://127.0.0.1:14000/dir
    acme_ca_root $TMP/pebble.crt
    email admin@limer.test
    log_level info
}

limer.test, www.limer.test {
    reverse_proxy 127.0.0.1:9801
}
CFG
./limer run -c "$TMP/Limerfile" >/dev/null 2>"$TMP/limer.log" & LIMER=$!; PIDS+=($LIMER)
wait_port 5443 || { echo "limer did not start"; cat "$TMP/limer.log"; exit 1; }
expect_contains "certificate manager started" "$(sleep 0.5; cat $TMP/limer.log)" "certificate manager started"

echo "# obtaining a certificate via http-01"
issuer=""
for _ in $(seq 1 60); do
    issuer=$(openssl s_client -connect 127.0.0.1:5443 -servername limer.test </dev/null 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
    case "$issuer" in *Pebble*) break;; esac
    sleep 0.5
done
expect_contains "served certificate is issued by Pebble" "$issuer" "Pebble"
expect_contains "account registered" "$(cat $TMP/limer.log)" "registered account"
expect_contains "challenge answered" "$(cat $TMP/limer.log)" "answering http-01 challenge for limer.test"
expect_contains "certificate obtained for both names" "$(cat $TMP/limer.log)" "obtained certificate for limer.test and others (2 names)"
san=$(openssl s_client -connect 127.0.0.1:5443 -servername www.limer.test </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null)
expect_contains "certificate covers www" "$san" "DNS:www.limer.test"
[ -s "$TMP/storage/certs/limer.test/cert.pem" ] && ok "certificate stored" || fail "certificate stored"
[ -s "$TMP/storage/acme/account.key" ] && ok "account key stored" || fail "account key stored"
expect_eq "challenge files cleaned up" "$(ls $TMP/storage/challenges 2>/dev/null | wc -l)" "0"
expect_eq "https site serves traffic" "$(curl -sk --resolve limer.test:5443:127.0.0.1 https://limer.test:5443/)" "hello from acme-backend"
expect_eq "cert verifies against Pebble's root" "$(curl -s -o /dev/null -w '%{http_code}' --cacert <(curl -sk https://127.0.0.1:15000/roots/0) --resolve limer.test:5443:127.0.0.1 https://limer.test:5443/)" "200"
r=$(curl -s -D - -o /dev/null -H 'Host: limer.test' http://127.0.0.1:5002/x)
expect_contains "http listener redirects to https" "$r" "Location: https://limer.test:5443/x"

echo "# restart reuses the stored certificate and account"
kill -TERM $LIMER; wait $LIMER 2>/dev/null
./limer run -c "$TMP/Limerfile" >/dev/null 2>"$TMP/limer2.log" & LIMER=$!; PIDS+=($LIMER)
wait_port 5443
sleep 1
expect_contains "stored certificate loaded at start" "$(cat $TMP/limer2.log)" "loaded certificate from"
issuer=$(openssl s_client -connect 127.0.0.1:5443 -servername limer.test </dev/null 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
expect_contains "served immediately after restart" "$issuer" "Pebble"
sleep 1
expect_eq "no new order when the certificate is fresh" "$(grep -c 'obtained certificate' $TMP/limer2.log)" "0"
kill -TERM $LIMER; wait $LIMER 2>/dev/null

echo; echo "acme tests: passed $PASS, failed $FAIL"
[ $FAIL -eq 0 ]
