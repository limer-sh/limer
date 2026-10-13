#!/usr/bin/env bash
# Feature tests for Caddy-style behaviour: virtual hosts, SNI, auto-https
# redirects, rewrites, basic auth, header directives, error/abort, logging,
# env substitution and imports, static files and compression.
set -u
cd "$(dirname "$0")/.."
export no_proxy='*' NO_PROXY='*'   # never send test traffic through an outbound proxy
unset https_proxy HTTPS_PROXY http_proxy HTTP_PROXY grpc_proxy
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
expect_contains "active health checks over tls report up" "$(curl -s http://127.0.0.1:9787/upstreams)" '"address":"127.0.0.1:9703","weight":1,"drained":false,"healthy":true'
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

echo "# rate limiting"
cat > "$TMP/rl.conf" <<CFG
{
    admin 127.0.0.1:9791
    log_level warn
}
:9790 {
    rate_limit site 1000r/s

    route {
        match path /limited
        rate_limit strict {
            key {remote_ip}
            rate 2r/s
            burst 3
        }
        respond "ok"
    }
    route {
        match path /perkey
        rate_limit perkey {
            key {header.X-Api-Key}
            rate 60r/m
            burst 2
            status 503
        }
        respond "ok"
    }
    route {
        match path /json
        rate_limit json {
            key {json.tenant}
            rate 1r/s
            burst 1
        }
        respond "ok"
    }
    respond "free"
}
CFG
$BIN run -c "$TMP/rl.conf" >/dev/null 2>&1 & RLP=$!; PIDS+=($RLP)
wait_port 9790
codes=$(for i in 1 2 3 4 5; do curl -s -o /dev/null -w '%{http_code} ' http://127.0.0.1:9790/limited; done)
expect_eq "burst allows 3 then limits" "$codes" "200 200 200 429 429 "
expect_contains "429 carries Retry-After" "$(curl -s -D - -o /dev/null http://127.0.0.1:9790/limited)" "Retry-After: 1"
sleep 1.1
expect_eq "tokens refill over time" "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9790/limited)" "200"
a=$(for i in 1 2 3; do curl -s -o /dev/null -w '%{http_code} ' -H 'X-Api-Key: a' http://127.0.0.1:9790/perkey; done)
b=$(for i in 1 2 3; do curl -s -o /dev/null -w '%{http_code} ' -H 'X-Api-Key: b' http://127.0.0.1:9790/perkey; done)
expect_eq "per-key limit: key a" "$a" "200 200 503 "
expect_eq "per-key limit: key b is independent" "$b" "200 200 503 "
j=$(for t in x x y; do curl -s -o /dev/null -w '%{http_code} ' -X POST -d "{\"tenant\":\"$t\"}" http://127.0.0.1:9790/json; done)
expect_eq "json field as rate limit key" "$j" "200 429 200 "
expect_eq "unlimited route unaffected" "$(curl -s http://127.0.0.1:9790/other)" "free"
expect_contains "rate limit metrics" "$(curl -s http://127.0.0.1:9791/metrics)" 'limer_rate_limit_total{worker="0",zone="strict",result="limited"}'
kill -TERM $RLP; wait $RLP 2>/dev/null

echo "# sticky sessions"
cat > "$TMP/sticky.conf" <<CFG
{
    log_level warn
}
:9792 {
    reverse_proxy 127.0.0.1:9701 127.0.0.1:9702 {
        lb_policy sticky_cookie session
    }
}
CFG
$BIN run -c "$TMP/sticky.conf" >/dev/null 2>&1 & STP=$!; PIDS+=($STP)
wait_port 9792
hdr=$(curl -s -D - -o /dev/null http://127.0.0.1:9792/)
expect_contains "first response sets the sticky cookie" "$hdr" "Set-Cookie: session="
expect_contains "cookie attributes" "$hdr" "Path=/; HttpOnly"
cookie=$(grep -i '^Set-Cookie' <<<"$hdr" | sed 's/Set-Cookie: //; s/;.*//' | tr -d '\r')
first=$(curl -s -b "$cookie" http://127.0.0.1:9792/)
same=1
for i in 1 2 3 4 5 6; do [ "$(curl -s -b "$cookie" http://127.0.0.1:9792/)" = "$first" ] || same=0; done
[ $same = 1 ] && ok "requests with the cookie stay on one upstream" || fail "requests with the cookie stay on one upstream"
expect_not_contains "no Set-Cookie when the cookie already matches" "$(curl -s -D - -o /dev/null -b "$cookie" http://127.0.0.1:9792/)" "Set-Cookie"
both=$(for i in 1 2 3 4 5 6; do echo "$(curl -s http://127.0.0.1:9792/)"; done | sort -u | wc -l)
expect_eq "cookie-less requests are spread" "$both" "2"
expect_contains "unknown cookie value gets a fresh assignment" "$(curl -s -D - -o /dev/null -b 'session=0000000000000000' http://127.0.0.1:9792/)" "Set-Cookie: session="
kill -TERM $STP; wait $STP 2>/dev/null

echo "# runtime admin api: drain, weights, overrides"
rm -rf "$TMP/adminstore"
cat > "$TMP/admin.conf" <<CFG
{
    admin 127.0.0.1:9794
    storage $TMP/adminstore
    log_level warn
}
:9793 {
    reverse_proxy 127.0.0.1:9701 127.0.0.1:9702
}
CFG
$BIN run -c "$TMP/admin.conf" >/dev/null 2>&1 & ADP=$!; PIDS+=($ADP)
wait_port 9794
A=http://127.0.0.1:9794
dist() { for i in $(seq 1 8); do echo "$(curl -s http://127.0.0.1:9793/)"; done | sort | uniq -c | tr -s ' ' | tr '\n' ';'; }
expect_contains "both upstreams serve before draining" "$(dist)" "4 hello from b"
expect_contains "drain upstream" "$(curl -s -X POST $A/upstreams/127.0.0.1:9702/drain)" '"drained":true'
sleep 0.4
expect_eq "drained upstream gets no traffic" "$(dist)" " 8 hello from a;"
expect_contains "status shows drained" "$(curl -s $A/upstreams)" '"address":"127.0.0.1:9702","weight":1,"drained":true,"healthy":false'
expect_contains "overrides listed" "$(curl -s $A/overrides)" '"address":"127.0.0.1:9702","drained":true'
expect_contains "undrain upstream" "$(curl -s -X POST $A/upstreams/127.0.0.1:9702/undrain)" '"drained":false'
sleep 0.4
expect_contains "traffic returns after undrain" "$(dist)" "4 hello from b"
expect_contains "set weight" "$(curl -s -X POST $A/upstreams/127.0.0.1:9701/weight/3)" '"weight":3'
sleep 0.4
expect_contains "weight applied live (3:1)" "$(dist)" "6 hello from a"
expect_eq "unknown upstream -> 404" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $A/upstreams/127.0.0.1:1/drain)" "404"
expect_eq "bad action -> 400" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $A/upstreams/127.0.0.1:9701/explode)" "400"
expect_eq "GET on action -> 405" "$(curl -s -o /dev/null -w '%{http_code}' $A/upstreams/127.0.0.1:9701/drain)" "405"
curl -s -X POST $A/upstreams/127.0.0.1:9702/drain >/dev/null
kill -TERM $ADP; wait $ADP 2>/dev/null
$BIN run -c "$TMP/admin.conf" >/dev/null 2>&1 & ADP=$!; PIDS+=($ADP)
wait_port 9794
expect_eq "overrides persist across restart (drain + weight)" "$(dist)" " 8 hello from a;"
expect_contains "persisted weight visible" "$(curl -s $A/upstreams)" '"address":"127.0.0.1:9701","weight":3'
expect_contains "clear overrides" "$(curl -s -X DELETE $A/overrides)" "cleared"
sleep 0.4
expect_contains "defaults restored after clearing" "$(dist)" "4 hello from b"
kill -TERM $ADP; wait $ADP 2>/dev/null
# multi-worker: a change on one worker reaches all workers via the master reload
sed -i 's/    admin 127.0.0.1:9794/    admin 127.0.0.1:9794\n    workers 2/' "$TMP/admin.conf"
$BIN run -c "$TMP/admin.conf" >/dev/null 2>&1 & ADP=$!; PIDS+=($ADP)
wait_port 9794; sleep 0.3
curl -s -X POST $A/upstreams/127.0.0.1:9702/drain >/dev/null
sleep 0.8
expect_eq "drain propagates to all workers" "$(for i in $(seq 1 16); do echo "$(curl -s http://127.0.0.1:9793/)"; done | sort -u)" "hello from a"
kill -TERM $ADP; wait $ADP 2>/dev/null

echo "# http/2 to upstreams and grpc passthrough"
if $BIN version | grep -q "http/2" && python3 -c "import grpc, grpc_tools" 2>/dev/null; then
    python3 tests/grpc_service.py serve 9805 grpc-a & PIDS+=($!)
    python3 tests/grpc_service.py serve 9806 grpc-b & PIDS+=($!)
    wait_port 9805; wait_port 9806
    cat > "$TMP/grpc.conf" <<CFG
{
    log_level warn
}
https://localhost:9795 {
    tls internal
    reverse_proxy h2c://127.0.0.1:9805 h2c://127.0.0.1:9806 {
        lb_policy round_robin
    }
}
:9796 {
    reverse_proxy 127.0.0.1:9805 {
        transport http {
            versions h2c
        }
    }
}
:9797 {
    reverse_proxy 127.0.0.1:9701
}
CFG
    $BIN run -c "$TMP/grpc.conf" >/dev/null 2>"$TMP/grpc.log" & GP=$!; PIDS+=($GP)
    wait_port 9795
    openssl s_client -connect 127.0.0.1:9795 -servername localhost </dev/null 2>/dev/null | openssl x509 > "$TMP/limer-localhost.crt" 2>/dev/null
    out=$(python3 tests/grpc_service.py call localhost:9795 --tls "$TMP/limer-localhost.crt" --sni localhost 2>&1)
    expect_contains "grpc unary call through limer (h2 in, h2c out)" "$out" "pong:hello:xff=127.0.0.1 server=grpc-"
    expect_contains "grpc trailing metadata preserved" "$out" "trailer-x-server=grpc-"
    expect_contains "grpc unary round robin reaches both" "$(for i in 1 2 3 4; do python3 tests/grpc_service.py call localhost:9795 --tls "$TMP/limer-localhost.crt" --sni localhost 2>&1; done | grep -o 'server=grpc-[ab]' | sort -u | tr '\n' ' ')" "server=grpc-a server=grpc-b"
    out=$(python3 tests/grpc_service.py call localhost:9795 --tls "$TMP/limer-localhost.crt" --sni localhost --stream 500 2>&1)
    expect_contains "grpc server streaming (500 messages)" "$out" "streamed 500 messages, last=tick 499"
    out=$(python3 tests/grpc_service.py call localhost:9795 --tls "$TMP/limer-localhost.crt" --sni localhost --fail 2>&1)
    expect_contains "grpc error status passes through in trailers" "$out" "error FAILED_PRECONDITION: nope from grpc-"
    # plain HTTP/2 with prior knowledge (h2c) on the client side, end to end to the h2c upstream
    expect_contains "h2c prior-knowledge grpc client to h2c upstream" "$(python3 tests/grpc_service.py call 127.0.0.1:9796 2>&1)" "pong:hello"
    r=$(curl -s --http2-prior-knowledge -o /dev/null -w '%{http_version} %{http_code}' http://127.0.0.1:9797/get)
    expect_eq "h2c prior-knowledge client to an http/1.1 upstream" "$r" "2 200"
    r=$(curl -s --http1.1 -o /dev/null -w '%{http_version} %{http_code}' http://127.0.0.1:9797/get)
    expect_eq "http/1.1 still served on the same plain listener" "$r" "1.1 200"
    # the same upstream over HTTP/1.1 from the client side
    r=$(curl -s --http1.1 -D - -o /dev/null -X POST -H 'content-type: application/grpc' -H 'te: trailers' --data-binary '' http://127.0.0.1:9796/limertest.Echo/Ping)
    expect_contains "h1 client sees the h2 upstream response as chunked with trailers" "$r" "Transfer-Encoding: chunked"
    # concurrency: many parallel unary calls multiplexed on one session
    okc=$(for i in $(seq 1 20); do python3 tests/grpc_service.py call localhost:9795 --tls "$TMP/limer-localhost.crt" --sni localhost >/dev/null 2>&1 & done; wait; echo done)
    expect_eq "20 parallel grpc calls complete" "$okc" "done"
    expect_contains "grpc calls succeeded after concurrency" "$(python3 tests/grpc_service.py call localhost:9795 --tls "$TMP/limer-localhost.crt" --sni localhost 2>&1)" "pong:hello"
    # streamed request bodies: bidirectional ping-pong and client streaming
    expect_contains "grpc bidirectional streaming (50 ping-pong messages)" "$(python3 tests/grpc_service.py call localhost:9795 --tls "$TMP/limer-localhost.crt" --sni localhost --chat 50 2>&1)" "chat 50 replies, last=echo:m49, extra=0"
    expect_contains "grpc bidirectional streaming over h2c" "$(python3 tests/grpc_service.py call 127.0.0.1:9796 --chat 20 2>&1)" "chat 20 replies, last=echo:m19"
    expect_contains "grpc client streaming (2000 messages)" "$(python3 tests/grpc_service.py call localhost:9795 --tls "$TMP/limer-localhost.crt" --sni localhost --sum 2000 2>&1)" "sum:1999000 count=2000"
    expect_eq "no errors logged" "$(grep -c "error" $TMP/grpc.log)" "0"
    kill -TERM $GP; wait $GP 2>/dev/null
else
    echo "  skip - HTTP/2 build or grpcio not available"
fi

echo "# streaming request bodies"
cat > "$TMP/stream.conf" <<CFG
{
    log_level warn
    admin off
}
:9798 {
    request_body {
        max_size 100m
    }
    route {
        match path /echo
        match json kind == x
        reverse_proxy 127.0.0.1:9702
    }
    reverse_proxy 127.0.0.1:9701
}
:9799 {
    request_body {
        max_size 100m
        mode buffer
    }
    reverse_proxy 127.0.0.1:9701
}
:9800 {
    max_body 100k
    reverse_proxy 127.0.0.1:9701
}
https://localhost:9801 {
    tls internal
    request_body {
        max_size 100m
    }
    reverse_proxy 127.0.0.1:9701
}
CFG
$BIN run -c "$TMP/stream.conf" >/dev/null 2>"$TMP/stream.log" & SP=$!; PIDS+=($SP)
wait_port 9798; wait_port 9801
head -c 20000000 /dev/urandom > "$TMP/upload.bin"
SUM=$(sha256sum "$TMP/upload.bin" | cut -d' ' -f1)
r=$(curl -s --data-binary @"$TMP/upload.bin" -H 'Content-Type: application/octet-stream' http://127.0.0.1:9798/upload)
expect_contains "20 MB upload streamed with Content-Length" "$r" "\"body_len\": 20000000"
expect_contains "streamed upload intact" "$r" "$SUM"
expect_contains "Content-Length framing preserved" "$r" "\"chunked\": false"
r=$(curl -s --data-binary @"$TMP/upload.bin" -H 'Transfer-Encoding: chunked' http://127.0.0.1:9798/upload)
expect_contains "chunked upload streamed as chunked" "$r" "\"chunked\": true"
expect_contains "chunked streamed upload intact" "$r" "$SUM"
# a route that inspects the body forces buffering: the upstream sees a Content-Length
r=$(curl -s -H 'Transfer-Encoding: chunked' -H 'Content-Type: application/json' --data-binary '{"kind":"x"}' http://127.0.0.1:9798/echo)
expect_contains "json matcher still routes on the body" "$r" "\"name\": \"b\""
expect_contains "body-inspecting route buffers (Content-Length upstream)" "$r" "\"Content-Length\": \"12\""
r=$(curl -s -H 'Transfer-Encoding: chunked' --data-binary 'plain' http://127.0.0.1:9798/echo)
expect_contains "non-matching body falls through, still buffered because of route order" "$r" "\"Content-Length\": \"5\""
r=$(curl -s -H 'Transfer-Encoding: chunked' --data-binary 'plain' http://127.0.0.1:9799/echo)
expect_contains "request_body mode buffer forces buffering" "$r" "\"Content-Length\": \"5\""
# streaming still enforces max_body
r=$(H -H 'Transfer-Encoding: chunked' --data-binary @"$TMP/big.txt" http://127.0.0.1:9800/upload)
expect_eq "max_body enforced while streaming a chunked body" "$r" "413"
r=$(H --data-binary @"$TMP/big.txt" http://127.0.0.1:9800/upload)
expect_eq "max_body enforced on Content-Length up front" "$r" "413"
r=$(H --data-binary 'small' http://127.0.0.1:9800/upload)
expect_eq "small bodies still fine" "$r" "200"
# upstream answers before reading the body: client gets the answer, nothing is poisoned
r=$(curl -s -D - --data-binary @"$TMP/upload.bin" http://127.0.0.1:9798/early)
expect_contains "early upstream response delivered" "$r" "HTTP/1.1 413"
expect_contains "early response closes the client connection" "$r" "Connection: close"
expect_eq "proxy healthy after early response" "$(H http://127.0.0.1:9798/get)" "200"
# HTTP/2 clients stream too, with and without content-length
r=$(curl -sk --http2 --data-binary @"$TMP/upload.bin" https://localhost:9801/upload)
expect_contains "h2 upload streamed to an http/1.1 upstream" "$r" "$SUM"
expect_contains "h2 upload keeps its Content-Length" "$r" "\"content_length\": \"20000000\""
r=$(curl -sk --http2 -H 'Transfer-Encoding: chunked' --data-binary @"$TMP/upload.bin" https://localhost:9801/upload)
expect_contains "h2 upload without content-length is chunked upstream" "$r" "\"chunked\": true"
expect_contains "h2 chunked upload intact" "$r" "$SUM"
# many concurrent uploads
okc=$( (for i in $(seq 1 8); do curl -s --data-binary @"$TMP/upload.bin" http://127.0.0.1:9798/upload | grep -c "$SUM" & done; wait) | tr -d '\n')
expect_eq "8 concurrent 20 MB uploads intact" "$okc" "11111111"
expect_eq "no errors logged" "$(grep -c "error" $TMP/stream.log)" "0"
kill -TERM $SP; wait $SP 2>/dev/null

echo "# response caching"
python3 tests/cacheback.py 9730 & PIDS+=($!)
wait_port 9730
cat > "$TMP/cache.conf" <<CFG
{
    admin 127.0.0.1:9792
    log_level warn
}
:9823 {
    encode gzip
    cache {
        stale 3s
        max_object 1m
    }
    reverse_proxy 127.0.0.1:9730
}
:9824 {
    reverse_proxy 127.0.0.1:9730
}
CFG
$BIN run -c "$TMP/cache.conf" >/dev/null 2>"$TMP/cache.log" & CAP=$!; PIDS+=($CAP)
wait_port 9823; wait_port 9792
# a max-age response is a MISS then a HIT with the same body
a=$(curl -s -D "$TMP/h1" http://127.0.0.1:9823/maxage); b=$(curl -s -D "$TMP/h2" http://127.0.0.1:9823/maxage)
expect_eq "max-age response is served identically on the second request" "$a" "$b"
expect_contains "first request is a MISS" "$(cat "$TMP/h1")" "X-Cache: MISS"
expect_contains "second request is a HIT" "$(cat "$TMP/h2")" "X-Cache: HIT"
expect_contains "a cache hit carries an Age header" "$(cat "$TMP/h2")" "Age:"
# a site without a cache block does not cache
c=$(curl -s http://127.0.0.1:9824/maxage); d=$(curl -s http://127.0.0.1:9824/maxage)
[ "$c" != "$d" ] && ok "a site without cache does not serve stale copies" || fail "no-cache site" "both '$c'"
# s-maxage is honoured
expect_eq "s-maxage cached" "$(curl -s http://127.0.0.1:9823/smaxage)" "$(curl -s http://127.0.0.1:9823/smaxage)"
# no-store, private and Set-Cookie responses are never cached
x=$(curl -s http://127.0.0.1:9823/nostore); y=$(curl -s http://127.0.0.1:9823/nostore)
[ "$x" != "$y" ] && ok "no-store is never cached" || fail "no-store" "both '$x'"
x=$(curl -s http://127.0.0.1:9823/private); y=$(curl -s http://127.0.0.1:9823/private)
[ "$x" != "$y" ] && ok "private is never cached" || fail "private" "both '$x'"
x=$(curl -s http://127.0.0.1:9823/setcookie); y=$(curl -s http://127.0.0.1:9823/setcookie)
[ "$x" != "$y" ] && ok "Set-Cookie responses are never cached" || fail "set-cookie" "both '$x'"
# HEAD is served from the cache populated by a GET's sibling, and never returns a body
curl -s http://127.0.0.1:9823/maxage >/dev/null
expect_eq "HEAD returns no body" "$(curl -s -I http://127.0.0.1:9823/maxage | grep -ic '^body-')" "0"
# compression is applied per client from one stored identity copy
curl -s -o /dev/null http://127.0.0.1:9823/large   # populate
g=$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip' http://127.0.0.1:9823/large)
expect_contains "a cached response is gzip-encoded for a client that asks" "$g" "Content-Encoding: gzip"
expect_contains "the gzip-served cached response is still a HIT" "$g" "X-Cache: HIT"
expect_eq "an identity client gets the cached body intact" "$(curl -s http://127.0.0.1:9823/large | head -c 5)" "LARGE"
# a client conditional request against a cached entry gets 304
et=$(curl -s -o /dev/null http://127.0.0.1:9823/etag; curl -s -D - -o /dev/null http://127.0.0.1:9823/etag | grep -i '^ETag' | tr -d '
')
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'If-None-Match: "v1"' http://127.0.0.1:9823/etag)
expect_eq "client revalidation against a cached ETag returns 304" "$code" "304"
# Vary: different variants are kept apart
va=$(curl -s -H 'X-Variant: a' http://127.0.0.1:9823/vary)
expect_contains "a Vary request is cached per variant value" "$va" "variant=a-"
expect_eq "the same variant is a hit" "$(curl -s -H 'X-Variant: a' http://127.0.0.1:9823/vary)" "$va"
vb=$(curl -s -H 'X-Variant: b' http://127.0.0.1:9823/vary)
expect_contains "a different Vary value is not served the stored variant" "$vb" "variant=b-"
expect_eq "the new variant is now the cached one" "$(curl -s -H 'X-Variant: b' http://127.0.0.1:9823/vary)" "$vb"
# stale-while-revalidate: once max-age=1 expires the stale copy is served while a refresh runs
base=$(curl -s http://127.0.0.1:9730/hits)   # bump nothing; just reach the backend directly
hits_before=$(curl -s http://127.0.0.1:9730/hits)
curl -s -o /dev/null http://127.0.0.1:9823/etag   # store (etag, max-age=1)
sleep 1.3
sc=$(curl -s -D - http://127.0.0.1:9823/etag)
expect_contains "a stale entry within the window is served as STALE" "$sc" "X-Cache: STALE"
sleep 0.5   # let the background revalidation finish
# after revalidation the entry is fresh again (served as HIT, not STALE)
expect_contains "the background refresh makes it fresh again" "$(curl -s -D - http://127.0.0.1:9823/etag)" "X-Cache: HIT"
# metrics expose cache counters
expect_contains "metrics expose cache hits" "$(curl -s http://127.0.0.1:9792/metrics)" "limer_cache_hits_total"
expect_eq "no errors logged" "$(grep -c ' error ' $TMP/cache.log)" "0"
kill -TERM $CAP 2>/dev/null; wait $CAP 2>/dev/null

echo "# traffic splitting and request mirroring"
python3 tests/backend.py 9708 stable & PIDS+=($!)
python3 tests/backend.py 9709 canary & PIDS+=($!)
: > "$TMP/mirror.rec"
python3 tests/backend.py 9710 shadow --record "$TMP/mirror.rec" & SHADOWP=$!; PIDS+=($SHADOWP)
wait_port 9708; wait_port 9709; wait_port 9710
cat > "$TMP/split.conf" <<CFG
{
    admin off
    log_level warn
}
:9820 {
    route {
        match split 20 header X-User
        reverse_proxy 127.0.0.1:9709
    }
    reverse_proxy 127.0.0.1:9708 {
        mirror 127.0.0.1:9710
    }
}
:9821 {
    route {
        match split 100 header X-User
        reverse_proxy 127.0.0.1:9709
    }
    reverse_proxy 127.0.0.1:9708
}
:9822 {
    route {
        match split 0 header X-User
        reverse_proxy 127.0.0.1:9709
    }
    reverse_proxy 127.0.0.1:9708
}
CFG
$BIN run -c "$TMP/split.conf" >/dev/null 2>"$TMP/split.log" & SPP=$!; PIDS+=($SPP)
wait_port 9820
# distribution: ~20% of distinct users to canary
canary=$(for u in $(seq 1 400); do curl -s -H "X-User: u$u" http://127.0.0.1:9820/; echo; done | grep -c canary)
[ "$canary" -ge 50 ] && [ "$canary" -le 110 ] && ok "split sends roughly 20% to canary ($canary/400)" || fail "split ~20%" "got $canary/400"
# sticky: the same user always lands on the same side
side1=$(curl -s -H "X-User: alice" http://127.0.0.1:9820/)
sticky=yes; for i in $(seq 1 10); do [ "$(curl -s -H 'X-User: alice' http://127.0.0.1:9820/)" = "$side1" ] || sticky=no; done
expect_eq "split assignment is sticky per key" "$sticky" "yes"
expect_eq "split 100 sends everything to canary" "$(curl -s -H 'X-User: x' http://127.0.0.1:9821/)" "hello from canary"
expect_eq "split 0 sends nothing to canary" "$(curl -s -H 'X-User: x' http://127.0.0.1:9822/)" "hello from stable"
# mirroring: every request to stable is copied to the shadow, response ignored
: > "$TMP/mirror.rec"
for i in 1 2 3 4 5; do curl -s -X POST --data "body$i" http://127.0.0.1:9820/echo >/dev/null; done
sleep 0.5
expect_eq "all requests reach the mirror" "$(grep -c POST "$TMP/mirror.rec")" "5"
expect_contains "mirror receives the request body" "$(cat "$TMP/mirror.rec")" "5 body3"
expect_eq "the client still gets the real upstream response" "$(curl -s http://127.0.0.1:9820/)" "hello from stable"
expect_contains "mirrored request carries the X-Mirrored-By marker" "$(cat "$TMP/mirror.rec")" "POST /echo"
# a dead mirror does not affect the client
kill "$SHADOWP" 2>/dev/null; wait "$SHADOWP" 2>/dev/null
expect_eq "client unaffected when the mirror upstream is down" "$(curl -s http://127.0.0.1:9820/)" "hello from stable"
expect_eq "mirror failure is not logged as an error" "$(grep -c ' error ' $TMP/split.log)" "0"
kill -TERM $SPP 2>/dev/null; wait $SPP 2>/dev/null

echo "# mutual tls: client certificates on sites and to upstreams"
MT="$TMP/mtls"; mkdir -p "$MT"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$MT/ca.key" -out "$MT/ca.crt" -days 2 \
    -subj "/O=Limer Test/CN=Limer Test CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$MT/other-ca.key" -out "$MT/other-ca.crt" -days 2 \
    -subj "/CN=Other CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
mkcert() { # mkcert NAME CA-PREFIX SUBJECT
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$MT/$1.key" -out "$MT/$1.csr" -subj "$3" >/dev/null 2>&1
    openssl x509 -req -in "$MT/$1.csr" -CA "$MT/$2.crt" -CAkey "$MT/$2.key" -CAcreateserial -out "$MT/$1.crt" -days 2 >/dev/null 2>&1
}
mkcert client ca "/O=Limer Test/OU=ops/CN=alice"
mkcert rogue other-ca "/CN=mallory"
cat > "$MT/Limerfile" <<CFG
{
    https_port 9815
    admin off
    log_level warn
}
mtls.test {
    tls internal {
        client_auth {
            mode require_and_verify
            trusted_ca_cert_file $MT/ca.crt
        }
    }
    header X-Client-Serial {tls_client_serial}
    respond "{tls_client_subject}|{tls_client_verified}|{tls_client_issuer}"
}
optional.test {
    tls internal {
        client_auth {
            mode request
            trusted_ca_cert_file $MT/ca.crt
        }
    }
    route {
        match tls_client verified == true
        respond "verified {tls_client_subject} fp={tls_client_fingerprint}"
    }
    route {
        match tls_client present == true
        respond "unverified {tls_client_subject}"
    }
    respond "anonymous"
}
strict.test {
    tls internal {
        client_auth {
            mode verify_if_given
            trusted_ca_cert_file $MT/ca.crt
        }
    }
    respond "strict {tls_client_present}"
}
open.test {
    tls internal
    respond "open site"
}
CFG
$BIN run -c "$MT/Limerfile" >/dev/null 2>"$MT/limer.log" & MTP=$!; PIDS+=($MTP)
wait_port 9815
R="--resolve mtls.test:9815:127.0.0.1 --resolve optional.test:9815:127.0.0.1 --resolve strict.test:9815:127.0.0.1 --resolve open.test:9815:127.0.0.1"
r=$(curl -sk $R --cert "$MT/client.crt" --key "$MT/client.key" https://mtls.test:9815/)
expect_eq "require_and_verify accepts a trusted client certificate" "$r" "CN=alice,OU=ops,O=Limer Test|true|CN=Limer Test CA,O=Limer Test"
expect_contains "serial placeholder in a header" "$(curl -sk $R --http1.1 -D - -o /dev/null --cert "$MT/client.crt" --key "$MT/client.key" https://mtls.test:9815/)" "X-Client-Serial: "
r=$(curl -sk $R -o /dev/null -w '%{http_code}' https://mtls.test:9815/ 2>&1)
expect_eq "require_and_verify rejects a client without a certificate" "$r" "000"
r=$(curl -sk $R -o /dev/null -w '%{http_code}' --cert "$MT/rogue.crt" --key "$MT/rogue.key" https://mtls.test:9815/ 2>&1)
expect_eq "require_and_verify rejects a certificate from another CA" "$r" "000"
expect_eq "sites without client_auth on the same listener stay open" "$(curl -sk $R https://open.test:9815/)" "open site"
expect_eq "request mode: anonymous clients pass" "$(curl -sk $R https://optional.test:9815/)" "anonymous"
expect_contains "request mode: verified clients match tls_client verified" "$(curl -sk $R --cert "$MT/client.crt" --key "$MT/client.key" https://optional.test:9815/)" "verified CN=alice,OU=ops,O=Limer Test fp="
expect_eq "request mode: untrusted certificates are seen but unverified" "$(curl -sk $R --cert "$MT/rogue.crt" --key "$MT/rogue.key" https://optional.test:9815/)" "unverified CN=mallory"
fp=$(openssl x509 -in "$MT/client.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
expect_contains "fingerprint placeholder matches openssl" "$(curl -sk $R --cert "$MT/client.crt" --key "$MT/client.key" https://optional.test:9815/)" "fp=$fp"
expect_eq "verify_if_given: no certificate is fine" "$(curl -sk $R https://strict.test:9815/)" "strict false"
expect_eq "verify_if_given: a trusted certificate is fine" "$(curl -sk $R --cert "$MT/client.crt" --key "$MT/client.key" https://strict.test:9815/)" "strict true"
r=$(curl -sk $R -o /dev/null -w '%{http_code}' --cert "$MT/rogue.crt" --key "$MT/rogue.key" https://strict.test:9815/ 2>&1)
expect_eq "verify_if_given rejects an untrusted certificate" "$r" "000"
expect_contains "http/2 streams see the client certificate" "$(curl -sk $R --http2 --cert "$MT/client.crt" --key "$MT/client.key" https://mtls.test:9815/)" "CN=alice"
kill -TERM $MTP; wait $MTP 2>/dev/null
# client certificates towards upstreams
mkcert upstream ca "/CN=127.0.0.1"
python3 tests/backend.py 9713 mtls-up --tls "$TMP/up.crt" "$TMP/up.key" --client-ca "$MT/ca.crt" & PIDS+=($!)
wait_port 9713
cat > "$MT/up.conf" <<CFG
{
    admin off
    log_level warn
}
:9816 {
    reverse_proxy https://127.0.0.1:9713 {
        tls_trusted_ca_certs $TMP/up.crt
        tls_client_auth $MT/client.crt $MT/client.key
    }
}
:9817 {
    reverse_proxy https://127.0.0.1:9713 {
        tls_trusted_ca_certs $TMP/up.crt
        lb_retries 0
    }
}
CFG
$BIN run -c "$MT/up.conf" >/dev/null 2>"$MT/up.log" & MUP=$!; PIDS+=($MUP)
wait_port 9816
expect_eq "client certificate presented to the upstream" "$(curl -s http://127.0.0.1:9816/)" "hello from mtls-up"
expect_eq "upstream requiring a certificate rejects a pool without one" "$(H http://127.0.0.1:9817/)" "502"
kill -TERM $MUP; wait $MUP 2>/dev/null

echo "# dynamic upstreams (dns a / srv, re-resolution)"
cat > "$TMP/zone.json" <<ZONE
{"backends.test": {"A": ["127.0.0.1", "127.0.0.2"]},
 "_http._tcp.svc.test": {"SRV": [[10, 1, 9701, "a.test"], [10, 3, 9702, "b.test"]]},
 "a.test": {"A": ["127.0.0.1"]}, "b.test": {"A": ["127.0.0.1"]},
 "moving.test": {"A": ["127.0.0.1"]}}
ZONE
python3 tests/dns_server.py 5354 "$TMP/zone.json" & DNSP=$!; PIDS+=($DNSP)
python3 tests/backend.py 9701 c --bind 127.0.0.2 & PIDS+=($!)
sleep 0.3
cat > "$TMP/dyn.conf" <<CFG
{
    log_level info
    admin 127.0.0.1:9791
    resolvers 127.0.0.1:5354
}
:9802 {
    reverse_proxy {
        dynamic a backends.test 9701 {
            refresh 1s
        }
    }
}
:9803 {
    reverse_proxy {
        dynamic srv _http._tcp.svc.test {
            refresh 1s
        }
    }
}
:9804 {
    reverse_proxy moving.test:9701 {
        refresh 1s
    }
}
CFG
$BIN run -c "$TMP/dyn.conf" >/dev/null 2>"$TMP/dyn.log" & DYP=$!; PIDS+=($DYP)
wait_port 9802; wait_port 9791
cat > "$TMP/ups.py" <<'PY'
import json, sys
d = json.load(sys.stdin)
print(" ".join(u["address"] + "/" + str(u["weight"]) for u in d["pools"][int(sys.argv[1])]["upstreams"]))
PY
ups() { curl -s http://127.0.0.1:9791/upstreams | python3 "$TMP/ups.py" "$1"; }
expect_eq "dynamic a resolves to both addresses" "$(ups 0)" "127.0.0.1:9701/1 127.0.0.2:9701/1"
r=$(for i in 1 2 3 4; do curl -s http://127.0.0.1:9802/; done)
expect_contains "requests reach the first address" "$r" "hello from a"
expect_contains "requests reach the second address" "$r" "hello from c"
expect_eq "dynamic srv gives targets, ports and weights" "$(ups 1)" "127.0.0.1:9701/1 127.0.0.1:9702/3"
r=$(for i in $(seq 1 8); do curl -s http://127.0.0.1:9803/; echo; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')
expect_contains "srv weights steer traffic 1:3" "$r" "2 hello from a;"
expect_contains "srv weights steer traffic 1:3 (b)" "$r" "6 hello from b;"
expect_eq "named static upstream resolved through resolvers" "$(curl -s http://127.0.0.1:9804/)" "hello from a"
expect_contains "admin shows the dynamic source" "$(curl -s http://127.0.0.1:9791/upstreams)" '"dynamic":{"type":"srv","name":"_http._tcp.svc.test","refresh":1}'
# change the records: one address leaves, another joins, the srv set shrinks, the static name moves
cat > "$TMP/zone.json" <<ZONE
{"backends.test": {"A": ["127.0.0.1", "127.0.0.3"]},
 "_http._tcp.svc.test": {"SRV": [[10, 5, 9702, "b.test"]]},
 "a.test": {"A": ["127.0.0.1"]}, "b.test": {"A": ["127.0.0.1"]},
 "moving.test": {"A": ["127.0.0.2"]}}
ZONE
sleep 2.5
expect_eq "address change applied on refresh" "$(ups 0)" "127.0.0.1:9701/1 127.0.0.3:9701/1"
expect_eq "srv member removed and weight updated" "$(ups 1)" "127.0.0.1:9702/5"
expect_eq "static name follows its new address" "$(curl -s http://127.0.0.1:9804/)" "hello from c"
r=$(for i in 1 2 3; do curl -s http://127.0.0.1:9803/; echo; done | sort -u)
expect_eq "removed srv member gets no traffic" "$r" "hello from b"
# runtime overrides apply to dynamic members too, and survive the next refresh
curl -s -X POST http://127.0.0.1:9791/upstreams/127.0.0.1:9702/weight/9 >/dev/null
sleep 1.5
expect_eq "weight override sticks across refreshes" "$(ups 1)" "127.0.0.1:9702/9"
curl -s -X DELETE http://127.0.0.1:9791/overrides >/dev/null
# a failing lookup keeps the last known set
kill $DNSP; wait $DNSP 2>/dev/null
sleep 2.5
expect_eq "lookup failure keeps the pool" "$(ups 0)" "127.0.0.1:9701/1 127.0.0.3:9701/1"
expect_contains "lookup failure is logged" "$(cat $TMP/dyn.log)" "keeping 2 upstreams"
python3 tests/dns_server.py 5354 "$TMP/zone.json" & DNSP=$!; PIDS+=($DNSP)
sleep 1
# reload keeps the resolved members (no gap) and the schedule
kill -HUP $DYP; sleep 0.5
expect_eq "reload keeps dynamic members" "$(ups 0)" "127.0.0.1:9701/1 127.0.0.3:9701/1"
expect_eq "reload keeps the re-resolved static address" "$(curl -s http://127.0.0.1:9804/)" "hello from c"
expect_eq "no errors logged" "$(grep -c " error " $TMP/dyn.log)" "0"
kill -TERM $DYP; wait $DYP 2>/dev/null

echo "# reload keeps virtual hosts"
sed -i 's/respond "two"/respond "two-v2"/' "$TMP/Limerfile"
kill -HUP $LIMER; sleep 0.5
expect_eq "reload applies to a virtual host" "$(curl -s -H 'Host: two.test' http://127.0.0.1:9782/)" "two-v2"
expect_eq "other hosts intact after reload" "$(curl -s -H 'Host: one.test' http://127.0.0.1:9782/)" "one"

if grep -q "Sanitizer\|runtime error" "$TMP/limer.log"; then fail "no sanitizer reports" "$(grep -m1 Sanitizer $TMP/limer.log)"; else ok "no sanitizer reports"; fi
echo; echo "feature tests: passed $PASS, failed $FAIL"
[ $FAIL -eq 0 ]
