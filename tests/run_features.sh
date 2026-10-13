#!/usr/bin/env bash
# Feature tests for Caddy-style behaviour: virtual hosts, SNI, auto-https
# redirects, rewrites, basic auth, header directives, error/abort, logging,
# env substitution and imports, static files and compression.
set -u
cd "$(dirname "$0")/.."
export no_proxy='*' NO_PROXY='*'   # never send test traffic through an outbound proxy
BIN=./limer
TMP=tests/tmp/features
rm -rf "$TMP"; mkdir -p "$TMP/site/sub" "$TMP/conf.d"
PASS=0; FAIL=0; PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
ok()   { PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL - $1"; [ -n "${2:-}" ] && echo "         ${2:0:300}"; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }
expect_contains() { case "$2" in *"$3"*) ok "$1";; *) fail "$1" "missing '$3' in: ${2:0:300}";; esac; }
expect_not_contains() { case "$2" in *"$3"*) fail "$1" "unexpected '$3' in: ${2:0:300}";; *) ok "$1";; esac; }
wait_port() { for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.05; done; return 1; }
H() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

make -s || exit 1
python3 tests/backend.py 9701 a & PIDS+=($!)
python3 tests/backend.py 9702 b & PIDS+=($!)
wait_port 9701; wait_port 9702

# bcrypt hash for "secret" (cost 5 to keep tests fast)
HASH=$(perl -e 'print crypt("secret", q{$2b$05$abcdefghijklmnopqrstuu})')
printf 'hello from index\n' > "$TMP/site/index.html"
printf 'sub page\n' > "$TMP/site/sub/page.txt"
head -c 20000 /dev/zero | tr '\0' 'x' > "$TMP/site/big.txt"
head -c 300000 /dev/urandom | base64 -w0 > "$TMP/big.txt"
printf 'secret\n' > "$TMP/site/.hidden"
printf 'respond "from import" 203\n' > "$TMP/conf.d/imported.conf"
export LIMER_TEST_MSG="env says hi"

cat > "$TMP/Limerfile" <<CFG
{
    http_port 9780
    https_port 9781
    admin off
    log_level warn
}

(security) {
    header X-Frame-Options DENY
    header -Server
    header +X-Snippet {args.0}
}

# plain-http catch-all on 9780 is NOT defined, so https sites get redirect sites there

# two https virtual hosts on one listener, distinguished by Host / SNI
alpha.test {
    tls internal
    import security alpha
    respond "alpha site"
}

beta.test, www.beta.test {
    tls internal
    import security beta
    header X-Site beta
    route {
        match path /echo /big /chunked /nolength /status/*
        reverse_proxy 127.0.0.1:9701
    }
    respond "beta site"
}

# plain http virtual hosts sharing :9782
http://one.test:9782 {
    log {
        output file $TMP/one.log
        format json
    }
    respond "one"
}
http://two.test:9782 {
    respond "two"
}
http://*.wild.test:9782 {
    respond "wild {host}"
}
:9782 {
    respond "catch-all"
}

# handlers
:9783 {
    log {
        output file $TMP/access.log
    }
    header X-Global yes
    request_header X-From-Server limer
    encode gzip {
        minimum_length 100
    }

    handle_path /api/* {
        request_header X-Route api
        reverse_proxy 127.0.0.1:9701 127.0.0.1:9702
    }
    handle /legacy/* {
        uri strip_prefix /legacy
        uri replace .php ""
        reverse_proxy 127.0.0.1:9701
    }
    route {
        match path /rw/*
        rewrite /echo?from={path}
        reverse_proxy 127.0.0.1:9701
    }
    route {
        match path /private/*
        basic_auth {
            bob $HASH
        }
        respond "secret area"
    }
    route {
        match path /gone
        error "it is gone" 410
    }
    route {
        match path /drop
        abort
    }
    route {
        match path /r
        redir /target permanent
    }
    route {
        match path /env
        respond "{\$LIMER_TEST_MSG}"
    }
    route {
        match path /imported
        import conf.d/imported.conf
    }
    route {
        match path /echo /chunked /big
        reverse_proxy 127.0.0.1:9701
    }
    respond "fallback" 200
}

# server-wide basic auth
:9784 {
    basic_auth realm1 {
        alice $HASH
    }
    respond "all protected"
}

# static files
:9785 {
    root $TMP/site
    encode zstd br gzip {
        minimum_length 100
    }
    handle_path /static/* {
        file_server browse
    }
    route {
        match path /spa/*
        try_files {path} /index.html
        file_server
    }
    file_server
}
CFG

out=$($BIN validate -c "$TMP/Limerfile" 2>&1); rc=$?
if [ $rc -eq 0 ]; then ok "feature config validates"; else fail "feature config validates" "$out"; cat "$TMP/Limerfile" | head -5; exit 1; fi
$BIN run -c "$TMP/Limerfile" >/dev/null 2>"$TMP/limer.log" & LIMER=$!; PIDS+=($LIMER)
wait_port 9782 || { echo "limer did not start"; cat "$TMP/limer.log"; exit 1; }

echo "# virtual hosts (plain http)"
expect_eq "host one" "$(curl -s -H 'Host: one.test' http://127.0.0.1:9782/)" "one"
expect_eq "host two" "$(curl -s -H 'Host: two.test:9782' http://127.0.0.1:9782/)" "two"
expect_eq "wildcard host" "$(curl -s -H 'Host: x.wild.test' http://127.0.0.1:9782/)" "wild x.wild.test"
expect_eq "host case-insensitive" "$(curl -s -H 'Host: TWO.test' http://127.0.0.1:9782/)" "two"
expect_eq "unknown host -> catch-all" "$(curl -s -H 'Host: nope.test' http://127.0.0.1:9782/)" "catch-all"
expect_eq "no host header -> catch-all" "$(curl -s --http1.0 -H 'Host:' http://127.0.0.1:9782/)" "catch-all"
expect_eq "keep-alive switches sites per request" "$(curl -s -H 'Host: one.test' http://127.0.0.1:9782/ -H 'Host: two.test' http://127.0.0.1:9782/ 2>/dev/null | head -c 3)" "one"

echo "# https virtual hosts, SNI and auto redirects"
expect_eq "alpha via SNI" "$(curl -sk --resolve alpha.test:9781:127.0.0.1 https://alpha.test:9781/)" "alpha site"
expect_eq "beta via SNI" "$(curl -sk --resolve beta.test:9781:127.0.0.1 https://beta.test:9781/)" "beta site"
expect_eq "www.beta via SNI" "$(curl -sk --resolve www.beta.test:9781:127.0.0.1 https://www.beta.test:9781/)" "beta site"
cn=$(curl -skv --resolve beta.test:9781:127.0.0.1 https://beta.test:9781/ 2>&1 | grep -o 'CN=[a-z.]*' | head -1)
expect_eq "SNI selects beta's certificate" "$cn" "CN=beta.test"
cn=$(curl -skv --resolve alpha.test:9781:127.0.0.1 https://alpha.test:9781/ 2>&1 | grep -o 'CN=[a-z.]*' | head -1)
expect_eq "SNI selects alpha's certificate" "$cn" "CN=alpha.test"
san=$(openssl s_client -connect 127.0.0.1:9781 -servername www.beta.test </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null)
expect_contains "internal cert carries SAN" "$san" "DNS:www.beta.test"
hdrs=$(curl -sk --http1.1 -D - -o /dev/null --resolve beta.test:9781:127.0.0.1 https://beta.test:9781/)
expect_contains "snippet import with args (header)" "$hdrs" "X-Snippet: beta"
expect_contains "header directive on site" "$hdrs" "X-Site: beta"
expect_contains "header X-Frame-Options" "$hdrs" "X-Frame-Options: DENY"
expect_not_contains "header -Server removes Server" "$hdrs" "Server:"
r=$(curl -s -D - -o /dev/null -H 'Host: alpha.test' http://127.0.0.1:9780/some/path?x=1)
expect_contains "http -> https redirect status" "$r" "HTTP/1.1 308"
expect_contains "redirect location keeps path and port" "$r" "Location: https://alpha.test:9781/some/path?x=1"
expect_eq "redirect site unknown host -> 404" "$(H -H 'Host: unknown.test' http://127.0.0.1:9780/)" "404"
r=$(curl -sk --resolve beta.test:9781:127.0.0.1 https://beta.test:9781/echo)
expect_contains "proxy over https site sets X-Forwarded-Proto https" "$r" '"X-Forwarded-Proto": "https"'

echo "# handlers"
B=http://127.0.0.1:9783
r=$(curl -s "$B/api/echo?x=1")
expect_contains "handle_path strips prefix" "$r" '"path": "/echo?x=1"'
expect_contains "request_header in route" "$r" '"X-Route": "api"'
expect_contains "request_header at server level" "$r" '"X-From-Server": "limer"'
expect_contains "handle_path exact prefix -> /" "$(curl -s $B/api/)" "hello from"
expect_eq "handle_path does not match the bare prefix" "$(curl -s $B/api)" "fallback"
r=$(curl -s "$B/legacy/echo.php?q=1")
expect_contains "uri strip_prefix + replace" "$r" '"path": "/echo?q=1"'
r=$(curl -s "$B/rw/x/y")
expect_contains "rewrite with placeholders" "$r" '"path": "/echo?from=/rw/x/y"'
expect_contains "header directive on all responses" "$(curl -s -D - -o /dev/null $B/echo)" "X-Global: yes"
expect_eq "basic_auth without credentials -> 401" "$(H $B/private/x)" "401"
expect_contains "WWW-Authenticate realm" "$(curl -s -D - -o /dev/null $B/private/x)" 'WWW-Authenticate: Basic realm="restricted"'
expect_eq "basic_auth wrong password -> 401" "$(H -u bob:wrong $B/private/x)" "401"
expect_eq "basic_auth unknown user -> 401" "$(H -u eve:secret $B/private/x)" "401"
expect_eq "basic_auth correct -> 200" "$(curl -s -u bob:secret $B/private/x)" "secret area"
expect_eq "basic_auth does not leak to other routes" "$(curl -s $B/fallback)" "fallback"
expect_eq "server-wide basic_auth" "$(H http://127.0.0.1:9784/)" "401"
expect_eq "server-wide basic_auth ok" "$(curl -s -u alice:secret http://127.0.0.1:9784/)" "all protected"
r=$(curl -s -D - $B/gone)
expect_contains "error directive status" "$r" "HTTP/1.1 410"
expect_contains "error directive message" "$r" "it is gone"
expect_eq "abort closes without response" "$(curl -s -o /dev/null -w '%{http_code}' $B/drop 2>/dev/null)" "000"
expect_eq "limer survives abort" "$(curl -s $B/fallback)" "fallback"
expect_contains "redir permanent" "$(curl -s -D - -o /dev/null $B/r)" "HTTP/1.1 301"
expect_eq "env substitution in config" "$(curl -s $B/env)" "env says hi"
expect_eq "import of a file inside a route" "$(H $B/imported)" "203"

echo "# logging"
curl -s -H 'Host: one.test' http://127.0.0.1:9782/logme >/dev/null
sleep 0.2
expect_contains "json access log" "$(tail -1 $TMP/one.log)" '"host":"one.test"'
expect_contains "json access log fields" "$(tail -1 $TMP/one.log)" '"uri":"/logme","proto":"HTTP/1.1","tls":false,"status":200'
expect_contains "common access log file" "$(tail -1 $TMP/access.log)" 'route='

echo "# static files"
F=http://127.0.0.1:9785
expect_eq "file_server index" "$(curl -s $F/)" "hello from index"
expect_eq "file_server nested file" "$(curl -s $F/sub/page.txt)" "sub page"
expect_eq "file_server 404" "$(H $F/nope.txt)" "404"
expect_eq "dotfiles hidden" "$(H $F/.hidden)" "404"
expect_eq "path traversal blocked" "$(H --path-as-is "$F/../Limerfile")" "404"
expect_eq "encoded traversal blocked" "$(H --path-as-is "$F/%2e%2e/Limerfile")" "404"
hdrs=$(curl -s -D - -o /dev/null $F/sub/page.txt)
expect_contains "content-type from extension" "$hdrs" "Content-Type: text/plain"
expect_contains "last-modified header" "$hdrs" "Last-Modified:"
expect_contains "etag header" "$hdrs" "ETag:"
etag=$(grep -i '^etag' <<<"$hdrs" | tr -d '\r' | cut -d' ' -f2)
expect_eq "if-none-match -> 304" "$(H -H "If-None-Match: $etag" $F/sub/page.txt)" "304"
expect_eq "range request" "$(curl -s -H 'Range: bytes=0-2' $F/sub/page.txt)" "sub"
expect_contains "range status 206" "$(curl -s -D - -o /dev/null -H 'Range: bytes=4-7' $F/sub/page.txt)" "HTTP/1.1 206"
expect_contains "content-range" "$(curl -s -D - -o /dev/null -H 'Range: bytes=4-7' $F/sub/page.txt)" "Content-Range: bytes 4-7/9"
expect_eq "unsatisfiable range -> 416" "$(H -H 'Range: bytes=100-200' $F/sub/page.txt)" "416"
expect_eq "HEAD on file" "$(curl -s -I $F/big.txt | grep -i content-length | tr -d '\r' | awk '{print $2}')" "20000"
expect_contains "directory browse listing" "$(curl -s $F/static/sub/)" "page.txt"
expect_contains "directory redirect adds slash" "$(curl -s -D - -o /dev/null $F/static/sub)" "Location: /static/sub/"
expect_eq "handle_path + file_server" "$(curl -s $F/static/sub/page.txt)" "sub page"
expect_eq "try_files SPA fallback" "$(curl -s $F/spa/some/route)" "hello from index"
expect_eq "big file intact" "$(curl -s $F/big.txt | wc -c)" "20000"
expect_contains "gzip encoding" "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip' $F/big.txt)" "Content-Encoding: gzip"
expect_eq "gzip body decodes" "$(curl -s --compressed $F/big.txt | wc -c)" "20000"
expect_contains "zstd preferred when offered" "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip, zstd' $F/big.txt)" "Content-Encoding: zstd"
expect_eq "zstd body decodes" "$(curl -s --compressed $F/big.txt | wc -c)" "20000"
expect_eq "gzip when only gzip is accepted" "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip' $F/big.txt | grep -i content-encoding | tr -d '\r' | awk '{print $2}')" "gzip"
expect_eq "q=0 disables an encoding" "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: zstd;q=0, gzip' $F/big.txt | grep -i content-encoding | tr -d '\r' | awk '{print $2}')" "gzip"
expect_contains "proxied response compressed" "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip' $B/echo)" "Content-Encoding: gzip"
expect_contains "proxied compressed body decodes" "$(curl -s --compressed $B/echo)" '"path": "/echo"'
expect_contains "proxied chunked response compressed and re-chunked" "$(curl -s -D - --compressed http://127.0.0.1:9783/chunked)" "alpha-beta-gamma"
head -c 3000 /dev/urandom > "$TMP/site/blob.bin"
expect_not_contains "non-compressible content left alone" "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip' $F/blob.bin)" "Content-Encoding"
expect_eq "large proxied body compressed intact" "$(curl -s --compressed $B/big | wc -c)" "3145728"
expect_contains "br encoding" "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: br' $F/big.txt)" "Content-Encoding: br"
expect_not_contains "small responses not compressed" "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip' $F/sub/page.txt)" "Content-Encoding"
expect_contains "Vary: Accept-Encoding" "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip' $F/big.txt)" "Vary: Accept-Encoding"
expect_not_contains "no encoding without Accept-Encoding" "$(curl -s -D - -o /dev/null $F/big.txt)" "Content-Encoding"

echo "# tls to upstreams"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$TMP/up.key" -out "$TMP/up.crt" -days 2 \
    -subj "/CN=backend.test" -addext "subjectAltName=DNS:backend.test,IP:127.0.0.1" >/dev/null 2>&1
python3 tests/backend.py 9703 tls-a --tls "$TMP/up.crt" "$TMP/up.key" & PIDS+=($!)
python3 tests/backend.py 9704 tls-b --tls "$TMP/up.crt" "$TMP/up.key" & PIDS+=($!)
wait_port 9703; wait_port 9704
cat > "$TMP/uptls.conf" <<CFG
{
    log_level warn
}
:9786 {
    route {
        match path /insecure
        reverse_proxy https://127.0.0.1:9703 {
            tls_insecure_skip_verify
        }
    }
    route {
        match path /verified /echo
        reverse_proxy https://127.0.0.1:9703 https://127.0.0.1:9704 {
            tls_trusted_ca_certs $TMP/up.crt
            tls_server_name backend.test
            health_uri /healthz
            health_interval 0.5s
        }
    }
    route {
        match path /badca
        reverse_proxy https://127.0.0.1:9703 {
            lb_retries 0
            max_fails 0
        }
    }
    route {
        match path /transport
        reverse_proxy 127.0.0.1:9703 {
            transport http {
                tls
                tls_insecure_skip_verify
            }
        }
    }
    route {
        match path /dead
        reverse_proxy https://127.0.0.1:9799 https://127.0.0.1:9704 {
            tls_insecure_skip_verify
            connect_timeout 1s
        }
    }
}
CFG
$BIN run -c "$TMP/uptls.conf" >/dev/null 2>"$TMP/uptls.log" & UP=$!; PIDS+=($UP)
wait_port 9786; sleep 0.8
U=http://127.0.0.1:9786
expect_eq "https upstream with insecure skip verify" "$(curl -s $U/insecure)" "hello from tls-a"
r=$(for i in 1 2 3 4; do echo "$(curl -s $U/verified)"; done | sort -u | tr '\n' ' ')
expect_eq "https upstreams verified against a trusted CA, round robin" "$r" "hello from tls-a hello from tls-b "
expect_contains "proxied over tls keeps request details" "$(curl -s $U/echo)" '"X-Forwarded-Proto": "http"'
expect_eq "untrusted upstream certificate -> 502" "$(H $U/badca)" "502"
expect_contains "verification failure is reported" "$(curl -s $U/badca)" "tls handshake"
expect_eq "transport http { tls } enables tls for plain upstreams" "$(curl -s $U/transport)" "hello from tls-a"
expect_eq "retry over tls after a dead upstream" "$(curl -s $U/dead)" "hello from tls-b"
r=$(curl -s -o /dev/null -o /dev/null -o /dev/null $U/verified $U/verified $U/verified -w '%{num_connects} ')
expect_eq "keep-alive to the client over tls upstreams" "$r" "1 0 0 "
cat > "$TMP/uptls-admin.conf" <<CFG
{
    admin 127.0.0.1:9787
    log_level warn
}
:9788 {
    reverse_proxy https://127.0.0.1:9703 https://127.0.0.1:9704 {
        tls_trusted_ca_certs $TMP/up.crt
        tls_server_name backend.test
        health_uri /healthz
        health_interval 0.3s
    }
}
CFG
$BIN run -c "$TMP/uptls-admin.conf" >/dev/null 2>&1 & UP2=$!; PIDS+=($UP2)
wait_port 9787; sleep 1
expect_contains "active health checks over tls report up" "$(curl -s http://127.0.0.1:9787/upstreams)" '"address":"127.0.0.1:9703","weight":1,"healthy":true'
kill -TERM $UP $UP2; wait $UP $UP2 2>/dev/null

echo "# http/2"
if $BIN version | grep -q "http/2"; then
    H2="curl -sk --http2 --resolve beta.test:9781:127.0.0.1 --resolve alpha.test:9781:127.0.0.1"
    expect_eq "h2 negotiated via ALPN" "$($H2 -o /dev/null -w '%{http_version}' https://beta.test:9781/)" "2"
    expect_eq "h2 local response" "$($H2 https://beta.test:9781/)" "beta site"
    expect_eq "h2 virtual host by :authority" "$($H2 https://alpha.test:9781/)" "alpha site"
    r=$($H2 -X POST -H 'Content-Type: application/json' -d '{"type":"order","customer":{"id":"h2"}}' https://beta.test:9781/echo)
    expect_contains "h2 proxied POST body intact" "$r" '"body": "{\"type\":\"order\",\"customer\":{\"id\":\"h2\"}}"'
    expect_contains "h2 request gets Content-Length upstream" "$r" '"Content-Length": "39"'
    expect_contains "h2 forwarding headers" "$r" '"X-Forwarded-Proto": "https"'
    expect_contains "h2 cookies joined" "$($H2 -H 'Cookie: a=1' -H 'Cookie: b=2' https://beta.test:9781/echo)" '"Cookie": "a=1; b=2"'
    expect_eq "h2 large response intact" "$($H2 https://beta.test:9781/big 2>/dev/null | wc -c)" "3145728"
    expect_eq "h2 large request body" "$($H2 -X POST --data-binary "@$TMP/big.txt" https://beta.test:9781/echo | python3 -c 'import sys,json;print(json.load(sys.stdin)["body_len"])')" "$(stat -c %s $TMP/big.txt)"
    expect_eq "h2 chunked upstream response" "$($H2 https://beta.test:9781/chunked)" "alpha-beta-gamma"
    expect_eq "h2 close-delimited upstream response" "$($H2 https://beta.test:9781/nolength)" "close-delimited body from a"
    expect_eq "h2 HEAD" "$($H2 -I https://beta.test:9781/big | grep -ci '^content-length: 3145728')" "1"
    expect_eq "h2 204" "$($H2 -o /dev/null -w '%{http_code}' https://beta.test:9781/status/204)" "204"
    expect_eq "h2 upstream 500 passthrough" "$($H2 -o /dev/null -w '%{http_code}' https://beta.test:9781/status/500)" "500"
    expect_eq "h2 multiplexed requests on one session" "$($H2 --parallel --parallel-max 10 -o /dev/null -o /dev/null -o /dev/null -o /dev/null -w '%{http_code} ' https://beta.test:9781/ https://beta.test:9781/big https://beta.test:9781/chunked https://beta.test:9781/echo)" "200 200 200 200 "
    expect_eq "h2 session reused across requests" "$($H2 -o /dev/null -o /dev/null -o /dev/null -w '%{num_connects} ' https://beta.test:9781/ https://beta.test:9781/echo https://beta.test:9781/)" "1 0 0 "
    expect_contains "h2 respond header ops" "$($H2 -D - -o /dev/null https://beta.test:9781/)" "x-site: beta"
    expect_eq "h1 still works on the same listener" "$(curl -sk --http1.1 --resolve beta.test:9781:127.0.0.1 -o /dev/null -w '%{http_version}' https://beta.test:9781/)" "1.1"
    # http/2 on the static/encode site: give it a tls listener
    cat > "$TMP/h2files.conf" <<CFG
{
    log_level warn
}
https://localhost:9789 {
    tls internal
    log {
        output file $TMP/h2.log
        format json
    }
    root $TMP/site
    encode gzip
    file_server browse
}
CFG
    $BIN run -c "$TMP/h2files.conf" >/dev/null 2>&1 & H2P=$!; PIDS+=($H2P)
    wait_port 9789
    expect_eq "h2 static file" "$(curl -sk --http2 https://localhost:9789/sub/page.txt)" "sub page"
    expect_eq "h2 big static file gzip decodes" "$(curl -sk --http2 --compressed https://localhost:9789/big.txt | wc -c)" "20000"
    expect_contains "h2 gzip header" "$(curl -sk --http2 -D - -o /dev/null -H 'Accept-Encoding: gzip' https://localhost:9789/big.txt)" "content-encoding: gzip"
    expect_eq "h2 range request" "$(curl -sk --http2 -H 'Range: bytes=0-2' https://localhost:9789/sub/page.txt)" "sub"
    expect_eq "h2 directory listing" "$(curl -sk --http2 https://localhost:9789/sub/ | grep -c page.txt)" "1"
    expect_eq "h2 404" "$(curl -sk --http2 -o /dev/null -w '%{http_code}' https://localhost:9789/nope)" "404"
    expect_eq "h2 parallel static" "$(curl -sk --http2 --parallel -o /dev/null -o /dev/null -o /dev/null -w '%{http_code} ' https://localhost:9789/big.txt https://localhost:9789/sub/page.txt https://localhost:9789/index.html)" "200 200 200 "
    sleep 0.2
    expect_contains "h2 json access log proto" "$(tail -1 $TMP/h2.log)" '"proto":"HTTP/2.0","tls":true'
    kill -TERM $H2P; wait $H2P 2>/dev/null
else
    echo "  skip - built without HTTP/2"
fi

echo "# reload keeps virtual hosts"
sed -i 's/respond "two"/respond "two-v2"/' "$TMP/Limerfile"
kill -HUP $LIMER; sleep 0.5
expect_eq "reload applies to a virtual host" "$(curl -s -H 'Host: two.test' http://127.0.0.1:9782/)" "two-v2"
expect_eq "other hosts intact after reload" "$(curl -s -H 'Host: one.test' http://127.0.0.1:9782/)" "one"

if grep -q "Sanitizer\|runtime error" "$TMP/limer.log"; then fail "no sanitizer reports" "$(grep -m1 Sanitizer $TMP/limer.log)"; else ok "no sanitizer reports"; fi
echo; echo "feature tests: passed $PASS, failed $FAIL"
[ $FAIL -eq 0 ]
