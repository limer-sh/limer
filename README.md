# Limer

Limer is a small, fast HTTP server and load balancer written in C with
**payload-based request distribution**. It routes and balances requests on
what is *inside* them: JSON fields, form fields, regexes over the body,
headers, cookies, the path, or the client address. It works like
[Caddy](https://caddyserver.com): one binary, a readable `Limerfile`,
automatic HTTPS, HTTP/2, static files, compression, `limer run` /
`validate` / `reload` / `stop`, zero-downtime reloads and an admin API.

```
example.com {
    # Same customer -> same upstream, chosen by a field in the JSON body
    route orders {
        match method POST
        match json type == order refund
        reverse_proxy 10.0.1.10:8080 10.0.1.11:8080 {
            lb_policy hash json customer.id
        }
    }

    handle_path /static/* {
        root /srv/www
        file_server
    }

    # Everything else: least-connections over three backends with health checks
    reverse_proxy 10.0.0.10:8080 10.0.0.11:8080 10.0.0.12:8080 {
        lb_policy least_conn
        health_uri /healthz
    }
}
```

That site gets a certificate from Let's Encrypt automatically, answers on
HTTPS with HTTP/2 and HTTP/1.1, and redirects plain HTTP to HTTPS.

## Features

- **Payload-based routing**: pick a handler by matching JSON fields (dot
  paths, `items[0].sku`), form fields, body regexes, headers, cookies, query
  parameters, method, path (globs or regex), host, or client IP/CIDR.
  Matchers in a route are AND-ed; values on one matcher are OR-ed. Operators:
  `==` `!=` `~` (regex) `!~` `>` `<` `>=` `<=` `^=` (prefix) `*=` (contains)
  `exists` `missing`, plus `match not ...`.
- **Payload-based balancing**: `lb_policy hash json <path>` (or `form`,
  `body`, `header`, `cookie`, `query`, `path`, `uri`, `client_ip`) uses
  weighted rendezvous hashing so a key always lands on the same upstream and
  only the keys of an upstream that goes away get remapped. Classic policies
  too: `round_robin` (smooth weighted), `least_conn`, `random`, `first`,
  `ip_hash`, `uri_hash`; per-upstream `weight=N`.
- **Reverse proxy**: keep-alive on both sides with an upstream connection
  pool, retries on other upstreams, active HTTP health checks and passive
  ejection, Caddy-style forwarding headers, `header_up`/`header_down`,
  WebSocket and `Upgrade` tunnelling, TLS to upstreams with verification.
- **Sites like Caddy's**: `example.com`, `www.example.com:8080`,
  `https://api.example.com`, `:8080`, `localhost`, wildcards. Sites sharing a
  port share one listener and are told apart by Host and SNI.
- **Automatic HTTPS**: sites with public hostnames obtain and renew
  certificates from Let's Encrypt (any ACME CA) over http-01; `localhost`
  and `tls internal` get self-signed certificates; HTTP redirects to HTTPS.
- **HTTP/2** (over TLS via ALPN, built on nghttp2) and HTTP/1.1 and 1.0.
- **Static files**: `root`, `file_server` (index files, `browse` listings),
  `try_files`, conditional requests, byte ranges, path traversal protection.
- **Compression**: `encode gzip zstd br` for proxied, static and local
  responses, streaming, honouring `Accept-Encoding` q-values.
- **Handlers and directives**: `handle`, `handle_path`, `route`, `respond`,
  `redir`, `error`, `abort`, `rewrite`, `uri strip_prefix|strip_suffix|replace`,
  `header`, `request_header`, `basic_auth` (bcrypt), `request_body`.
- **Config conveniences**: `{$ENV}` substitution, `import` of files and
  globs, snippets `(name) { }` with `{args.N}`, per-site `log { output;
  format json|common }`.
- **Operations**: `limer validate`, hot reload on `SIGHUP` / `limer reload` /
  `POST /reload` (bad configs are rejected and the old one keeps running),
  graceful shutdown with a grace period, multi-process `workers` with
  `SO_REUSEPORT`, pidfile, access logs, admin API with JSON upstream status
  and Prometheus metrics.
- **HTTP/1.1 done properly**: pipelining, chunked bodies both ways,
  `Expect: 100-continue`, HEAD/204/304 framing, close-delimited responses,
  request-smuggling guards, bounded buffering with backpressure.
- Dependencies: libc; OpenSSL for TLS/ACME, nghttp2 for HTTP/2, zlib/zstd/
  brotli for compression, all optional and auto-detected. Linux (epoll).

## Building

```
make            # builds ./limer with whatever optional libraries are found
make TLS=0      # force a build without OpenSSL (no HTTPS, ACME or HTTP/2)
make H2=0       # build without nghttp2
make ENCODE=0   # build without compression
make check      # unit tests, fuzzing, integration, feature, ACME and security suites
make install    # installs to /usr/local/bin
limer version   # prints which optional features are compiled in
```

On Debian/Ubuntu the optional libraries are `libssl-dev libnghttp2-dev
zlib1g-dev libzstd-dev libbrotli-dev` (plus `pkg-config`).

## Running

```
limer run                     # uses ./Limerfile or /etc/limer/Limerfile
limer run -c path/Limerfile   # explicit config
limer validate -c Limerfile   # parse, resolve upstreams, load certificates
limer reload                  # SIGHUP the running instance (needs `pidfile`)
limer stop                    # graceful SIGTERM
limer version
```

`limer run` stays in the foreground and logs to stderr (access logs to
stdout by default), which is what you want under systemd, Docker, or a
supervisor.

Try it locally with the bundled test backend:

```
python3 tests/backend.py 9001 shard-a &
python3 tests/backend.py 9002 shard-b &
python3 tests/backend.py 9003 shard-c &
./limer run -c examples/payload-routing.Limerfile
curl -X POST localhost:8080/echo -d '{"tenant":"acme","event":"signup"}'
curl localhost:2019/upstreams
```

## The Limerfile

The syntax follows the Caddyfile: one directive per line, blocks open with
`{` at the end of a line and close with `}` on their own line, `#` starts a
comment, values with spaces are quoted, `{$VAR}` and `{$VAR:default}` are
replaced from the environment.

```
# optional global options, must come first
{
    workers auto              # worker processes; default 1
    admin 127.0.0.1:2019      # admin API listener; "off" to disable
    log_level info            # debug | info | warn | error
    max_connections auto      # per worker; auto = half the descriptor limit
    pidfile /run/limer.pid
    grace 10s                 # drain time on shutdown
    http_port 80              # port for plain http and ACME challenges
    https_port 443
    email admin@example.com   # ACME account contact
    storage /var/lib/limer    # certificates and ACME state
    acme_ca https://acme-v02.api.letsencrypt.org/directory
    auto_https on             # off | disable_redirects
}

# snippets can be imported into any block, with {args.N} substitution
(security) {
    header X-Frame-Options DENY
    header X-Content-Type-Options nosniff
}

example.com, www.example.com {
    import security
    ...
}

import sites.d/*.conf
```

### Site addresses

| Address | Meaning |
|---|---|
| `example.com` | HTTPS on `https_port` with an automatic certificate; HTTP on `http_port` redirects here |
| `example.com:8443`, `https://example.com` | HTTPS on that port |
| `http://example.com`, `example.com:80` | plain HTTP for that host |
| `localhost`, `*.localhost` | HTTPS with a self-signed certificate |
| `:8080`, `127.0.0.1:8080`, `[::1]:8080` | plain HTTP, any host |
| `*.example.com` | wildcard host (needs `tls internal` or `tls <cert> <key>`) |

Several addresses can share one block (`a.com, b.com {`). Sites on the same
port share a listener; the Host header (and SNI for TLS) picks the site:
exact match, then wildcard, then the site without a hostname.

### Site directives

| Directive | Meaning |
|---|---|
| `tls <cert.pem> <key.pem>` | Use your own certificate. |
| `tls internal` | Self-signed certificate for the site's names. |
| `tls <email>` | Automatic certificate with this account email. |
| `log [{ output stdout|stderr|<file>; format json|common }]` | Access log for this site. |
| `header [+|-]Name [value]` or `header { ... }` | Set, add or delete response headers on every response. |
| `request_header [+|-]Name [value]` | Same for requests sent upstream. |
| `basic_auth [realm] { user <bcrypt-hash> ... }` | Protect the whole site (`htpasswd -nbB user pass`). |
| `encode [gzip] [zstd] [br] [{ minimum_length N }]` | Compress eligible responses; server order is the preference. |
| `root <dir>` | Default root for `file_server` in this site. |
| `max_body <size>` / `request_body { max_size <size> }` | Largest request body (`8m`); bodies are buffered so routing can inspect them. |
| `read_timeout <dur>` / `idle_timeout <dur>` | Request read time (`30s`) and keep-alive idle time (`2m`). |
| `reverse_proxy [upstreams...] [{ ... }]` | Catch-all proxy. |
| `respond`, `redir`, `error`, `abort`, `file_server` | Catch-all static handlers (see below). |
| `route [name|/pattern] { ... }`, `handle [/pattern] { ... }` | Matchers plus one handler. |
| `handle_path /prefix/* { ... }` | Like `handle`, and strips the prefix. |

Routes and catch-all handlers are evaluated in order; the first match wins.
Requests that match nothing get `404`.

### Matchers (inside a route)

```
match [not] <source> [name] [operator] [values...]
```

| Source | Needs a name | Examples |
|---|---|---|
| `method` | no | `match method POST PUT` |
| `path` | no | `match path /api/* /v2/*`, `match path ~ ^/v[0-9]+/` |
| `host` | no | `match host api.example.com *.example.org` |
| `remote_ip` | no | `match remote_ip 10.0.0.0/8 192.168.1.5` |
| `header` | yes | `match header X-Tenant acme`, `match header Authorization exists` |
| `query` | yes | `match query region eu us` |
| `cookie` | yes | `match cookie beta == 1` |
| `json` | yes (path) | `match json type order`, `match json order.total >= 100`, `match json items[0].sku ^= SKU-` |
| `form` | yes | `match form action checkout` (urlencoded bodies) |
| `body` | no | `match body ~ "priority=(high|urgent)"` |
| `uri` | no | `match uri *= "debug=1"` |

Without an operator, `==` is assumed; `==` with no values means `exists`.
Path and host use glob matching with `*`. Regexes are POSIX extended.

### Handlers (inside a route, or standalone as catch-alls)

| Directive | Meaning |
|---|---|
| `reverse_proxy <upstreams...> [{ options }]` or `to <upstreams...>` | Proxy to a pool. `https://host` or `transport http { tls }` proxies over TLS. |
| `respond [status] [body]` / `respond <body> [status]` | Static response; placeholders allowed. |
| `redir <location> [code|permanent|temporary]` | Redirect (`302` default). |
| `error [message] <status>` | Error response. |
| `abort` | Close the connection without a response. |
| `file_server [browse] { root; index; browse }` | Serve files from `root`. |
| `try_files <candidates...>` | With `file_server`: first existing file wins (`try_files {path} /index.html`). |
| `rewrite <uri>` | Replace path and query (placeholders allowed). |
| `uri strip_prefix <p>` / `uri strip_suffix <s>` / `uri replace <a> <b>` | Edit the path before the handler runs. |
| `basic_auth`, `header`, `request_header` | As at site level, scoped to the route. |

### Proxy options (inside `reverse_proxy { }` or a proxy route)

| Directive | Default | Meaning |
|---|---|---|
| `lb_policy <policy> [args]` | `round_robin` | See below. |
| `lb_retries <n>` | `2` | Extra upstreams to try when a connection fails before any response byte. |
| `max_fails <n>` / `fail_timeout <dur>` | `3` / `10s` | Passive health: eject an upstream after `n` consecutive failures. `max_fails 0` disables. |
| `unhealthy_status 5xx` | off | Count 5xx responses as passive failures. |
| `health_uri <path>` | off | Active health check URL. |
| `health_interval` / `health_timeout` | `10s` / `5s` | Check cadence and timeout. |
| `health_status <code>` | any 2xx/3xx | Expected status. |
| `health_host <host>` | upstream address | `Host` header for checks. |
| `connect_timeout` / `response_timeout` | `5s` / `60s` | Dial timeout and time to first response byte (`504` on expiry). |
| `keepalive_idle <n>` / `keepalive_timeout <dur>` | `256` / `60s` | Idle upstream connections to pool per upstream; `0` disables pooling. |
| `header_up [+|-]Name [value]` / `header_down ...` | | Edit request / response headers. |
| `preserve_host on|off` | `on` | Pass the client's `Host` through. |
| `tls_insecure_skip_verify`, `tls_server_name <name>`, `tls_trusted_ca_certs <pem>` | | Upstream TLS verification. |
| `transport http { keepalive_idle_conns N; tls; ... }` | | Caddy-compatible spelling of the above. |

Header values, `respond` bodies, `redir` targets, `rewrite` and
`try_files` accept placeholders: `{remote_ip}`, `{host}`, `{path}`,
`{query}`, `{uri}`, `{method}`, `{scheme}`, `{route}`,
`{upstream_hostport}`, `{upstream_host}`, `{header.Name}`.

### Load balancing policies

| Policy | Behaviour |
|---|---|
| `round_robin` | Smooth weighted round robin. |
| `least_conn` | Fewest in-flight requests (weighted), random tie-break. |
| `random` | Weighted random. |
| `first` | First healthy upstream in order (failover). |
| `ip_hash` | Hash of the client IP. |
| `uri_hash` | Hash of the request URI. |
| `hash <source> [name]` | Rendezvous hash of an extracted key: `hash json customer.id`, `hash form cart_id`, `hash header X-Session`, `hash cookie sid`, `hash query user`, `hash body`, `hash path`, `hash client_ip`. `payload` is an alias for `hash`. |

When the hash key is missing from a request, that request falls back to round
robin. Unhealthy upstreams are skipped, so their keys spill over to the
next-best upstream and return when the upstream recovers.

Limer always forwards `X-Forwarded-For` (appending), `X-Forwarded-Proto`,
`X-Forwarded-Host` and `X-Real-IP`, strips hop-by-hop headers, and keeps
`Upgrade` requests working (WebSockets are tunnelled after a `101`).

## Automatic HTTPS

A site whose address is a public hostname gets a certificate without any
TLS configuration:

1. Limer starts with a temporary self-signed certificate so the listener is
   up immediately, plus an http listener on `http_port` that redirects to
   https and answers ACME http-01 challenges.
2. A certificate manager process registers an ACME account (`email`),
   orders a certificate for all of the site's names, proves control over
   each over http-01, stores `cert.pem` and `key.pem` under
   `<storage>/certs/<host>/`, and reloads the server.
3. It checks every hour and renews 30 days before expiry, or when the stored
   certificate no longer covers the site's names.

Requirements: port 80 reachable from the internet (or `http_port` mapped to
it), DNS pointing at the server, and a writable `storage` directory. Use
`acme_ca` to point at another CA (staging, or
[Pebble](https://github.com/letsencrypt/pebble) for tests, with
`acme_ca_root` for its certificate). Wildcard names cannot be validated
over http-01: give them `tls <cert> <key>`. `auto_https off` disables
certificate management; `auto_https disable_redirects` keeps it but drops
the http redirect.

## Admin API

Enable with `admin <addr>` in the global block.

| Endpoint | Returns |
|---|---|
| `GET /health` | `{"status":"ok"}` |
| `GET /upstreams` | JSON: every pool, policy, hash key, and per-upstream health, in-flight requests, counters. |
| `GET /metrics` | Prometheus text format. |
| `GET /config` | The running Limerfile. |
| `POST /reload` | Reload the configuration from disk. |

With `workers > 1`, counters are per worker (each response names its worker).

## Reloading and signals

| Signal | Effect |
|---|---|
| `SIGHUP` | Reload the Limerfile. Listeners are kept or added; sites and pools are swapped atomically; in-flight requests finish on the old config; a config that fails to parse or bind is rejected and logged. |
| `SIGTERM` / `SIGINT` | Stop accepting, finish in-flight requests within `grace`, exit. |

With `workers N`, a master process supervises `N` workers that each own all
listeners via `SO_REUSEPORT`, restarts crashed workers, forwards `SIGHUP`
and `SIGTERM`, and runs the certificate manager.

## Testing

`make check` runs six suites; `make check-asan` runs them on a build
instrumented with AddressSanitizer and UndefinedBehaviorSanitizer. The
GitHub Actions workflow in `.github/workflows/ci.yml` runs both on every push.

| Target | What it covers |
|---|---|
| `make unit` | `tests/unit.c`: buffers, parsing helpers, CIDR matching, globbing, the HTTP head parsers (including every smuggling guard), the chunked decoder, the JSON path extractor, the Limerfile parser (site addresses, imports, snippets, every directive and ~60 rejected inputs), matchers and key extraction, and every balancing policy. |
| `make fuzz` | `tests/fuzz.c`: a mutation fuzzer over the HTTP parsers, chunked decoder, JSON extractor, form/cookie extraction and config parser with invariant checks; reproducible by seed. |
| `make integration` | `tests/run_tests.sh`: end-to-end proxying behaviour against Python backends: routing, hashing, weights, framing, keep-alive, pipelining, timeouts, retries, health checks, WebSocket upgrade, admin API, reload, graceful stop, TLS and multi-worker mode. |
| `make features` | `tests/run_features.sh`: virtual hosts, SNI, redirects, handlers, basic auth, logging, static files, compression, TLS to upstreams, HTTP/2 and reload. |
| `make acme` | `tests/run_acme.sh`: certificate issuance, storage and reuse against Pebble (skips when Pebble is not installed). |
| `make security` | `tests/security_tests.py`: the black-box security suite described below. |

## Security

Limer sits in front of your application, so it is strict about HTTP framing
and defensive about everything a client or upstream can send. The security
suite exercises each of these against a running instance, including a
scripted hostile upstream and a wire-level fuzz round, and verifies the
proxy keeps serving after every attack.

- **Request smuggling**: a message with both `Content-Length` and
  `Transfer-Encoding`, conflicting `Content-Length` values, any transfer
  coding other than exactly `chunked`, whitespace before a header colon,
  obsolete line folding, or a non-numeric length is rejected with `400` and
  the connection is closed. Bodies are always re-framed with a fresh
  `Content-Length` upstream; trailers are dropped.
- **Malformed input**: NUL bytes and control characters in heads, invalid
  header names, HTTP/0.9 or HTTP/2 request lines on an HTTP/1 connection,
  and binary garbage are rejected. Absolute-form targets are normalised.
- **Limits**: request heads above 64 KiB (`431`), more than 128 headers,
  bodies above `max_body` (`413`), chunk sizes that overflow, slow clients
  (`408` after `read_timeout`), silent keep-alive connections
  (`idle_timeout`), `max_connections` per worker, accept backoff when the
  process runs out of descriptors, HTTP/2 stream and header-list limits,
  bounded JSON nesting, streamed responses with backpressure.
- **Header hygiene**: hop-by-hop headers and any header nominated by
  `Connection` are stripped in both directions; `X-Forwarded-For` is
  appended to while `X-Real-IP`, `X-Forwarded-Proto` and `X-Forwarded-Host`
  are always set by the proxy; header values can never contain CR or LF.
- **Static files**: paths are percent-decoded and normalised before use,
  `..` can never escape `root`, dotfiles are hidden.
- **Hostile upstreams**: responses with conflicting framing, invalid chunk
  sizes, NUL bytes, oversized heads, bogus status lines, unsolicited `101`s
  or a closed connection become a clean `502`; a bodiless response that
  still advertises a body is never pooled.
- **Admin API isolation**: the admin endpoints exist only on the `admin`
  listener; bind it to localhost or a management network.
- **Memory safety**: the suites run clean under AddressSanitizer,
  UndefinedBehaviorSanitizer and Valgrind, and the fuzzer runs on every CI
  build.

## Performance

`bench/run.sh` reproduces these numbers. It builds a minimal epoll backend
(`bench/backend.c`), starts two of them, and drives Limer with
[wrk](https://github.com/wg/wrk) (and h2load when installed) over loopback.
Measured on a 4-vCPU Linux VM with wrk using 2 threads, 8-second runs,
keep-alive on:

| Scenario | Requests/s | p50 | p99 |
|---|---|---|---|
| wrk to backend directly (no proxy) | 152,000 | 0.58 ms | 2.0 ms |
| Limer, 1 worker, GET round robin, 100 connections | 33,000 | 2.8 ms | 6.3 ms |
| Limer, 1 worker, POST with JSON match + payload hash | 34,000 | 2.7 ms | 5.6 ms |
| Limer, 1 worker, GET, 1000 connections | 27,000 | 36 ms | 66 ms |
| Limer, 4 workers, GET round robin, 100 connections | 102,000 | 0.80 ms | 4.3 ms |
| Limer, 4 workers, POST with JSON match + payload hash | 98,000 | 0.83 ms | 5.4 ms |
| Limer, 4 workers, GET, 1000 connections | 116,000 | 7.4 ms | 19 ms |

Over TLS with h2load (10 connections, 10 streams each): HTTP/2 serves about
22,000 req/s per worker and 61,000 req/s with 4 workers; HTTP/1.1 over TLS
about 27,000 req/s per worker.

### Compared with Caddy

`bench/run.sh` also benchmarks Caddy when a `caddy` binary is on the PATH,
using `bench/Caddyfile` (the same two backends, `lb_policy round_robin`,
and an enlarged upstream keep-alive pool so Caddy is not limited by its
default of 32 idle connections per host). Same VM, same wrk settings,
Caddy v2.10.0:

| Scenario | Caddy | Limer | Ratio |
|---|---|---|---|
| 1 core, GET round robin, 100 connections | 9,200 req/s, p50 9.7 ms | 32,000 req/s, p50 2.9 ms | 3.5x |
| 1 core, POST 120 B JSON | 8,600 req/s, p50 10 ms | 31,000 req/s, p50 3.0 ms (with JSON match + hash) | 3.6x |
| 1 core, GET, 1000 connections | 7,400 req/s, p99 329 ms | 26,000 req/s, p99 72 ms | 3.5x |
| 4 cores, GET round robin, 100 connections | 23,500 req/s, p50 3.9 ms | 103,000 req/s, p50 0.80 ms | 4.4x |
| 4 cores, POST 120 B JSON | 20,500 req/s, p50 4.5 ms | 90,000 req/s, p50 0.91 ms (with JSON match + hash) | 4.4x |
| 4 cores, GET, 1000 connections | 22,500 req/s, p99 103 ms | 115,000 req/s, p99 20 ms | 5.1x |

Caddy was run with `auto_https off` and `admin off`, GOMAXPROCS pinned to
the core count, and HTTP/1.1 clients only (wrk does not speak HTTP/2).
This compares only the HTTP/1.1 reverse-proxy data path.

### Connection capacity

Each client connection costs one file descriptor and about 3 KB of memory
while idle (5 KB once it has served a request). Each request in flight
additionally needs one upstream descriptor. At startup every worker raises
its descriptor limit to the hard limit and, unless `max_connections` is set,
caps client connections at half of it so an accepted connection can always
reach an upstream; connections beyond the cap are closed immediately rather
than queued. Measured on the same VM (hard limit 20,000 descriptors):

| Test | Result |
|---|---|
| 18,000 keep-alive connections opened, one request each (in waves of 1,000) | all served; 55 MB idle, 90 MB after serving |
| New requests while 18,000 connections sit idle | p50 0.14 ms, p99 0.75 ms |
| 9,900 requests in flight simultaneously on one worker | all served in 1.1 s |
| 12,000 connections against a cap of 9,968 | 9,968 served, 2,032 closed at accept |

With a typical production limit of 1,048,576 descriptors, one worker can
hold roughly 500,000 connections in about 2.5 GB; use `workers auto` to
spread them over cores.

## Compared with Caddy: what is and is not there

Present: reverse proxy with health checks and all common balancing policies
(plus payload hashing, which Caddy lacks), site addresses and virtual hosts,
automatic HTTPS (http-01), HTTP/2, static files, compression, the common
handler directives, Caddyfile-style config with imports and snippets,
reloads, metrics, multi-process workers.

Not there: HTTP/3, DNS-01 and TLS-ALPN-01 challenges (so no wildcard
certificates from ACME), on-demand TLS, client certificate authentication,
templates, FastCGI, the JSON config API and the plugin ecosystem.

## Layout

```
src/limer.h    shared types
src/main.c     CLI, master/worker supervision
src/config.c   Limerfile tokenizer, imports/snippets, block parser, validation
src/proxy.c    epoll loop, client/upstream state machines, files, health checks, admin API, reload
src/h2.inc     HTTP/2 sessions and streams (nghttp2), included by proxy.c
src/acme.c     ACME client and certificate manager
src/tls.c      OpenSSL glue: certificates, SNI, internal certs, upstream contexts
src/http.c     HTTP/1.x head parsing, chunked coding
src/json.c     JSON path extraction
src/match.c    matchers and key extraction
src/balance.c  balancing policies, passive health accounting
src/encode.c   gzip/zstd/brotli response compression
src/files.c    MIME types, HTTP dates, directory listings
src/auth.c     basic authentication (bcrypt)
tests/         unit tests, parser fuzzer, integration, feature, ACME and security suites, test backend
bench/         wrk/h2load benchmark (run.sh), minimal C backend, benchmark configs
examples/      annotated Limerfiles
```
