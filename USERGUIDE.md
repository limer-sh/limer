# limer.sh

limer.sh is an ultra-fast HTTP server and load balancer written in C with
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
  WebSocket and `Upgrade` tunnelling, TLS to upstreams with verification and
  client certificates, cookie-based sticky sessions, and HTTP/2 to upstreams
  (`h2c://`, `h2://`) with trailers intact, so gRPC (including bidirectional
  streaming) passes through.
- **Streaming request bodies**: large uploads and bidirectional gRPC are
  forwarded as they arrive, with backpressure both ways, unless a matcher,
  hash key or placeholder needs to read the body (then it is buffered).
- **Dynamic upstreams**: a pool can come from DNS, `dynamic a <name> <port>`
  (one upstream per A/AAAA record) or `dynamic srv <name>` (SRV targets with
  their ports and weights), re-resolved on an interval; named upstreams are
  re-resolved too. Point lookups at specific `resolvers`.
- **Mutual TLS**: require or request client certificates per site
  (`tls { client_auth { ... } }`), match and log them, and present a client
  certificate to upstreams (`tls_client_auth`).
- **Traffic splitting and mirroring**: send a deterministic, sticky
  percentage of traffic to a canary with `match split <pct>`, or shadow a
  copy of each request to another pool with `mirror` and discard the reply.
- **Response caching**: an in-memory LRU cache (`cache { }`) honouring
  `Cache-Control`, `Expires`, `Vary`, `ETag`/`Last-Modified` revalidation
  and stale-while-revalidate.
- **Rate limiting**: token buckets per site or per route, keyed by any
  placeholder (`{remote_ip}`, `{header.X-Api-Key}`, `{json.tenant}`...),
  with `Retry-After` on rejection.
- **DoS mitigation**: `ip_guard` caps concurrent connections and the
  new-connection rate per source IP at accept time, and auto-bans sources
  that repeatedly trip the limits or a rate limit; `trusted_proxies` makes
  all of this (and `remote_ip`, `X-Real-IP`) key on the real client behind a
  CDN or load balancer.
- **Sites like Caddy's**: `example.com`, `www.example.com:8080`,
  `https://api.example.com`, `:8080`, `localhost`, wildcards. Sites sharing a
  port share one listener and are told apart by Host and SNI.
- **Automatic HTTPS**: sites with public hostnames obtain and renew
  certificates from Let's Encrypt (any ACME CA) over http-01, tls-alpn-01 or
  dns-01 (wildcards included, through a script hook); `localhost` and
  `tls internal` get self-signed certificates; HTTP redirects to HTTPS.
- **HTTP/3** over QUIC on every HTTPS port (`http3` in the global block,
  built on ngtcp2 and nghttp3), advertised with `Alt-Svc`; **HTTP/2** (over
  TLS via ALPN, or cleartext h2c with prior knowledge, built on nghttp2);
  and HTTP/1.1 and 1.0.
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
  `POST /reload` (bad configs are rejected and the old one keeps running;
  a reload keeps DNS-resolved upstreams and tolerates a name that is briefly
  unresolvable), graceful shutdown with a grace period, multi-process
  `workers` with `SO_REUSEPORT`, pidfile, access logs, admin API with JSON
  upstream status, Prometheus metrics (upstreams, rate-limit zones, cache),
  and runtime drain / weight overrides that survive reloads.
- **Safe deploys**: a master process supervises the workers and restarts a
  crashed one from the last-known-good config; `limer upgrade` swaps the
  binary with no downtime and the same pid; with `auto_rollback`, new
  configs and binaries run as a canary and are reverted automatically if
  they cause 5xx — and the rejected file is moved aside so a restart cannot
  bring it back.
- **Autoscaling hooks**: `scale_up` runs a command when the request rate or
  connection count spikes; a backend shutting down calls `POST /drain` to
  stop receiving new requests.
- **HTTP/1.1 done properly**: pipelining, chunked bodies both ways,
  `Expect: 100-continue`, HEAD/204/304 framing, close-delimited responses,
  request-smuggling guards, bounded buffering with backpressure.
- **Upstream status policy**: `retry_status 404 503` asks the next upstream
  when one answers with a listed status, and `redirect_on 404 /` turns the
  final answer into a redirect when no upstream had it.
- Dependencies: libc; OpenSSL for TLS/ACME, nghttp2 for HTTP/2, ngtcp2 +
  nghttp3 + GnuTLS for HTTP/3, zlib/zstd/brotli for compression, all
  optional and auto-detected. Linux (epoll) and macOS (kqueue).

## Building

```
make            # builds ./limer with whatever optional libraries are found
make TLS=0      # force a build without OpenSSL (no HTTPS, ACME or HTTP/2)
make H2=0       # build without nghttp2
make H3=0       # build without HTTP/3 (ngtcp2, nghttp3, GnuTLS)
make ENCODE=0   # build without compression
make check      # all fourteen test suites (see Testing)
make install    # installs to /usr/local/bin
limer version   # prints which optional features are compiled in
```

On Debian/Ubuntu the optional libraries are `libssl-dev libnghttp2-dev
zlib1g-dev libzstd-dev libbrotli-dev` (plus `pkg-config`). HTTP/3 needs
ngtcp2 (with its GnuTLS crypto library, `libngtcp2_crypto_gnutls`), nghttp3
and GnuTLS 3.7 or later; where the distribution's packages are too old,
build ngtcp2 and nghttp3 from source with `./configure --with-gnutls` and
make sure `pkg-config` finds them. `limer version` lists `http/3` when it is
compiled in.

### macOS

limer.sh builds and runs on macOS (Apple silicon and Intel), so you can run
the same Limerfile on a MacBook that you deploy to a Linux server. The event
loop uses kqueue there instead of epoll.

```
brew install pkgconf openssl@3 nghttp2 zstd brotli libxcrypt
make
./limer run -c Limerfile
```

- The Makefile finds Homebrew's keg-only OpenSSL and libxcrypt by itself.
  libxcrypt is required: it provides bcrypt for `basic_auth`, which the
  system `crypt()` lacks.
- HTTP/3: Homebrew's ngtcp2 is built for OpenSSL, not GnuTLS, so the build
  leaves HTTP/3 out unless you build ngtcp2 `--with-gnutls` from source (as
  on Linux, plus `brew install gnutls libnghttp3`).
- `workers` share listening sockets the master binds before it forks, because
  macOS hands every connection on a port to the socket bound last (its
  `SO_REUSEPORT` does not balance); Linux binds in each worker and lets the
  kernel spread the connections. A site address added by a reload is served by
  one worker until the next start. Zero-downtime `limer upgrade`, reloads,
  canaries and rollback all work.
- The descriptor limit is `kern.maxfilesperproc` (61,440 by default), so the
  default `max_connections` is about 30,000.
- Production numbers in this guide are from Linux; a Mac is for development.

## Running

```
limer run                     # uses ./Limerfile or /etc/limer/Limerfile
limer run -c path/Limerfile   # explicit config
limer validate -c Limerfile   # parse, resolve upstreams, load certificates
limer reload                  # SIGHUP the running instance (needs `pidfile`)
limer upgrade                 # swap in a new binary with no downtime (SIGUSR2)
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
    admin 127.0.0.1:2019      # admin API listener; "off" to disable; { secret ... } (see Admin API)
    log_level info            # debug | info | warn | error
    max_connections auto      # per worker; auto = half the descriptor limit
    pidfile /run/limer.pid
    grace 10s                 # drain time on shutdown
    http_port 80              # port for plain http and ACME challenges
    https_port 443
    email admin@example.com   # ACME account contact
    storage /var/lib/limer    # certificates and ACME state
    acme_ca https://acme-v02.api.letsencrypt.org/directory
    acme_challenge http-01    # tls-alpn-01 | dns-01
    acme_dns_script /etc/limer/dns-hook.sh   # for dns-01 (see Automatic HTTPS)
    acme_dns_propagation 30s
    auto_https on             # off | disable_redirects
    resolvers 10.0.0.2 10.0.0.3   # DNS servers for upstream lookups (default: system)
    cache_capacity 64m        # total response-cache size per worker
    trusted_proxies 10.0.0.0/8    # believe X-Forwarded-For from these hops (see below)
    ip_guard { }              # per-source-IP DoS mitigation (see below)
    server_header off         # Server header on limer's own responses; off = omit (default)
    auto_rollback { }         # canary new configs/binaries and revert ones that cause 5xx (see below)
    scale_up { }              # run a command when load spikes (see below)
    http3                     # also serve HTTP/3 over QUIC on every https port (see below)
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
| `tls ... { client_auth { mode <m>; trusted_ca_cert_file <pem> } }` | Require or request client certificates (mutual TLS). |
| `log [{ output stdout|stderr|<file>; format json|common }]` | Access log for this site. |
| `header [+|-]Name [value]` or `header { ... }` | Set, add or delete response headers on every response. |
| `request_header [+|-]Name [value]` | Same for requests sent upstream. |
| `basic_auth [realm] { user <bcrypt-hash> ... }` | Protect the whole site (`htpasswd -nbB user pass`). |
| `encode [gzip] [zstd] [br] [{ minimum_length N }]` | Compress eligible responses; server order is the preference. A response that says `Cache-Control: no-transform` and an event stream (`text/event-stream`) go as they are. |
| `rate_limit [zone] [rate] [{ key; rate; burst; status; max_keys }]` | Limit requests per key for the whole site (see Rate limiting). |
| `cache [{ ttl <dur>; stale <dur>; max_object <size> }]` | Cache proxied GET/HEAD responses (see Response caching). |
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
| `tls_client` | yes (field) | `match tls_client verified == true`, `match tls_client subject *= "OU=ops"` |
| `split` | no (pct [+ key]) | `match split 5`, `match split 10 header X-User` |

Without an operator, `==` is assumed; `==` with no values means `exists`.
Path and host use glob matching with `*`. Regexes are POSIX extended.

### Handlers (inside a route, or standalone as catch-alls)

| Directive | Meaning |
|---|---|
| `reverse_proxy <upstreams...> [{ options }]` or `to <upstreams...>` | Proxy to a pool. `https://host` or `transport http { tls }` proxies over TLS; `h2c://host` and `h2://host` speak HTTP/2 to the upstream. |
| `respond [status] [body]` / `respond <body> [status]` | Static response; placeholders allowed. |
| `redir <location> [code|permanent|temporary]` | Redirect (`302` default). |
| `error [message] <status>` | Error response. |
| `abort` | Close the connection without a response. |
| `file_server [browse] { root; index; browse }` | Serve files from `root`. |
| `try_files <candidates...>` | With `file_server`: first existing file wins (`try_files {path} /index.html`). |
| `rewrite <uri>` | Replace path and query (placeholders allowed). |
| `uri strip_prefix <p>` / `uri strip_suffix <s>` / `uri replace <a> <b>` | Edit the path before the handler runs. |
| `basic_auth`, `header`, `request_header`, `rate_limit` | As at site level, scoped to the route. |

### Proxy options (inside `reverse_proxy { }` or a proxy route)

| Directive | Default | Meaning |
|---|---|---|
| `lb_policy <policy> [args]` | `round_robin` | See below. |
| `lb_retries <n>` | `2` | Extra upstreams to try when a connection fails before any response byte. |
| `retry_status <codes...>` | off | Also try the next upstream when one answers with a listed status (`retry_status 404 503`); bounded by `lb_retries`, each upstream asked at most once. See Retrying and redirecting on status. |
| `redirect_on <codes...> <target> [code\|permanent\|temporary]` | off | When the final answer has a listed status, send a redirect to `target` instead (placeholders allowed; `302` default). |
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
| `tls_client_auth <cert.pem> <key.pem>` | | Present a client certificate to the upstream. |
| `dynamic a <name> <port>` / `dynamic srv <name>` | | Populate the pool from DNS (see Dynamic upstreams). |
| `refresh <dur>` | `30s` | Re-resolution interval for dynamic and named upstreams (`off` to pin). |
| `mirror <upstreams...> [{ sample <pct> }]` | | Shadow a copy of each request to another pool; the reply is discarded. |
| `transport http { keepalive_idle_conns N; tls; versions h2|h2c|1.1; ... }` | | Caddy-compatible spelling of the above; `versions h2c` or `h2` makes every upstream in the pool HTTP/2. |

Header values, `respond` bodies, `redir` targets, `rewrite` and
`try_files` accept placeholders: `{remote_ip}`, `{host}`, `{path}`,
`{query}`, `{uri}`, `{method}`, `{scheme}`, `{route}`,
`{upstream_hostport}`, `{upstream_host}`, `{header.Name}`, and (on TLS
connections) `{tls_client_subject}`, `{tls_client_issuer}`,
`{tls_client_serial}`, `{tls_client_fingerprint}`, `{tls_client_verified}`.

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
| `sticky_cookie [name]` | Cookie-based sticky sessions: the first request is balanced round robin and the response sets `name` (`limer_sticky`) to an opaque upstream id; later requests carrying it go to the same upstream while it is healthy. |
| `cookie [name [secret]]` | Caddy's spelling of the same sticky sessions, with Caddy's default cookie name `lb`; a secret is accepted and ignored. To balance on a cookie the application already sets, use `hash cookie <name>`. |

When the hash key is missing from a request, that request falls back to round
robin. Unhealthy upstreams are skipped, so their keys spill over to the
next-best upstream and return when the upstream recovers.

limer.sh always forwards `X-Forwarded-For` (appending), `X-Forwarded-Proto`,
`X-Forwarded-Host` and `X-Real-IP`, strips hop-by-hop headers, and keeps
`Upgrade` requests working (WebSockets are tunnelled after a `101`).

### HTTP/2 upstreams and gRPC

```
grpc.example.com {
    reverse_proxy h2c://10.0.0.5:50051 h2c://10.0.0.6:50051
}
```

Requests to an `h2c://` (cleartext) or `h2://` (TLS, ALPN `h2`) upstream are
multiplexed as streams on one HTTP/2 session per upstream, and the response
including its trailers is handed back to the client: an HTTP/2 client gets
real trailers (`grpc-status`, `grpc-message`, trailing metadata, and a
trailers-only error stays trailers-only), an HTTP/1.1 client gets a chunked
response with the trailers at the end. Clients may use TLS with ALPN or
plain HTTP/2 with prior knowledge on an http listener, so gRPC works without
TLS on either side. Unary, server-streaming, client-streaming and
bidirectional calls all work: request bodies stream through (see below), so
a route that does not inspect the body forwards gRPC frames as they arrive.
A route whose matcher, hash key or placeholder reads the body buffers it
first, which suits unary and server-streaming but not long-lived client
streams. Active health checks are plain HTTP/1.1 and need an upstream that
still answers HTTP/1.1; for h2-only upstreams rely on passive health.

### Retrying and redirecting on status

When objects are spread over several backends, or a backend answers `503`
while it warms up, `retry_status` lets another upstream answer instead:

```
assets.example.com {
    reverse_proxy 10.0.0.5:8080 10.0.0.6:8080 10.0.0.7:8080 {
        lb_policy first
        retry_status 404 503         # not here? ask the next one
        redirect_on 404 https://www.example.com/not-found?from={path}
    }
}
```

- A listed status from one upstream makes limer.sh discard that response
  and send the request to an upstream it has not asked yet, up to
  `lb_retries` extra attempts (default 2). The request body is replayed,
  so buffered POSTs retry too; a request whose body is being streamed
  (see Streaming request bodies) is not retried, because the bytes are
  already gone.
- The listed response does not count as a failure for passive health; use
  `unhealthy_status 5xx` for that.
- When every candidate gave a listed status, the last response is passed to
  the client as it is, or, with `redirect_on`, replaced by a redirect
  (`permanent` = 301, `temporary` = 302, or any 3xx code). The target
  accepts placeholders such as `{path}` and `{query}`.
- `redirect_on` works without `retry_status` too, as a fallback page for a
  single backend.

### Rate limiting

```
api.example.com {
    rate_limit site 1000r/s             # one bucket for the whole site
    route {
        match path /login
        rate_limit login {
            key {remote_ip}             # one bucket per client
            rate 5r/m
            burst 5
            status 429
        }
        reverse_proxy 10.0.0.2:8080
    }
}
```

Each `rate_limit` is a zone of token buckets: `rate` tokens per second or
minute (`10r/s`, `600r/m`) refill a bucket of `burst` tokens (default: the
per-second rate, at least 1), one bucket per distinct `key` (default: a
single shared bucket). Keys accept every placeholder, so limits can be per
client, per API key, per tenant in the JSON body, or per route. Rejected
requests get `status` (`429`) with `Retry-After`, and zones are capped at
`max_keys` (`100000`) buckets with least-recently-used eviction. Counts are
per worker. `/metrics` exposes allowed and limited totals per zone.

### DoS mitigation (connection guard)

`ip_guard` turns away abusive sources at the edge, before any HTTP parsing,
to blunt application-layer (L7) floods. It is not volumetric DDoS protection:
a single host cannot absorb a flood that saturates its uplink — put
network-layer scrubbing (a CDN, your provider) in front for that.

```
{
    trusted_proxies 10.0.0.0/8   # see below; set this when behind a proxy
    ip_guard {
        max_conns_per_ip 100     # cap concurrent connections per source IP
        conn_rate 50r/s          # new connections per second per source IP
        conn_burst 100           # bucket for conn_rate (default: the rate)
        ban_threshold 10         # strikes within the window that trigger a ban
        ban_window 10s           # how long strikes are counted over (default 10s)
        ban_duration 5m          # how long a banned address stays out
        max_keys 1000000         # addresses tracked before LRU eviction
    }
}
```

The guard works in two layers:

- **At accept, keyed on the TCP peer**: `max_conns_per_ip` caps concurrent
  connections and `conn_rate` limits new ones (a token bucket of `conn_burst`).
  A connection over either limit is dropped before it costs anything, and the
  source earns a *strike*.
- **After the request head, keyed on the effective client IP**: a banned
  client is turned away (`403`, or the connection is refused at accept when
  the client is the direct peer), and a request rejected by a `rate_limit`
  zone earns a strike too. An address that collects `ban_threshold` strikes
  within `ban_window` is banned for `ban_duration` — a fail2ban-style
  escalation that caps repeat offenders without banning on a single spike.

Any subset works: set only `max_conns_per_ip`, only `conn_rate`, or only the
`ban_*` knobs. Counts and bans are per worker (like `rate_limit`). The admin
listener is never guarded. `/metrics` exposes
`limer_ipguard_{admitted,refused,bans,tracked}`.

#### trusted_proxies and the client IP

By default limer treats the immediate TCP peer as the client. Behind a CDN or
another load balancer that is wrong: every connection's peer is the proxy, so
per-IP limits and bans would land on the proxy itself. List the proxy
addresses (IPs or CIDRs) in `trusted_proxies` and limer derives the real
client from `X-Forwarded-For` — the right-most address that is not itself a
trusted proxy. That effective client IP then drives the `remote_ip` matcher,
the `{remote_ip}` placeholder, `rate_limit` keys, the `X-Real-IP` sent
upstream, and the guard's bans. With `trusted_proxies` unset (the default),
nothing changes: the client IP is always the peer. Because the client IP is
only known once the head is read, the connection-level caps (`max_conns_per_ip`,
`conn_rate`) always key on the direct peer; behind a trusted proxy they guard
the proxy connection, and you rely on `rate_limit` plus bans for per-client
limits.

### Scale-up hook

`scale_up` runs a command when load spikes, so an autoscaler, an orchestrator
or a webhook can add backends before the existing ones are overwhelmed.

```
{
    scale_up {
        requests 1000r/s     # request rate that counts as a spike
        connections 5000     # and/or open client connections
        sustain 10s          # must stay above the threshold this long (default 0)
        cooldown 60s         # minimum time between runs (default 60s)
        exec "/etc/limer/scale-up.sh"
    }
}
```

The command runs through `sh -c`, detached from the server, with the trigger
in its environment: `LIMER_SCALE_REASON` (`requests` or `connections`),
`LIMER_SCALE_RATE` and `LIMER_SCALE_CONNS`. A hook might be as small as
`curl -X POST https://ops.example.com/scale -d "$LIMER_SCALE_RATE"` or an
`aws autoscaling set-desired-capacity` call. `exec` is required, and so is
a threshold unless the admin API is on. Worker 0 does the measuring, so with
`workers N` the rate is that worker's share of the traffic (roughly the
total divided by `N`).

Applications can ask for capacity too: `POST /scale_up` on the admin API
runs the same hook with `LIMER_SCALE_REASON=webhook` and
`LIMER_SCALE_CALLER` set to the caller's address. Automatic and webhook runs
share one cooldown across every worker, so a burst of calls still runs the
hook once per `cooldown`; protect the endpoint with a secret (see
[Securing the admin API](#securing-the-admin-api)).

The other half of scaling is taking a backend out of rotation gracefully: see
the self-drain endpoints in the [Admin API](#admin-api).

### Streaming request bodies

A proxied request's body is streamed to the upstream as it arrives, with
backpressure in both directions, so a large upload or a bidirectional gRPC
stream never buffers in full. A request is streamed only when nothing on the
matched route needs the body: a `json`/`form`/`body` matcher, a `hash` on one
of those, a rate-limit key or a header placeholder that reads the body all
force buffering (bounded by `max_body`). `request_body { mode buffer }`
forces buffering for a whole site; `mode stream` is the default.

### Dynamic upstreams

```
{ resolvers 10.0.0.2 }            # optional: use specific DNS servers
api.example.com {
    reverse_proxy {
        dynamic srv _http._tcp.api.svc.cluster.local
        refresh 10s
    }
}
backend.example.com {
    reverse_proxy {
        dynamic a backends.internal 8080   # one upstream per A/AAAA record
        refresh 30s
    }
}
```

`dynamic a <name> <port>` resolves a hostname to one upstream per address;
`dynamic srv <name>` uses SRV records, taking each target's port and weight.
The pool is re-resolved every `refresh` interval (default 30s, `off` to
pin): new addresses are added, vanished ones are drained and removed once no
request, connection, health check or HTTP/2 session still uses them, and a
failed lookup keeps the last known set. A named static upstream
(`reverse_proxy api.internal:8080`) is re-resolved on the same interval and
switches address when its record changes. `resolvers` points lookups at
specific servers (plain DNS, IPv4, optional `:port`); without it the system
resolver and `/etc/hosts` apply. Runtime drain/weight overrides and reloads
carry across re-resolution.

### Mutual TLS

```
api.example.com {
    tls internal {
        client_auth {
            mode require_and_verify            # request | require | verify_if_given
            trusted_ca_cert_file /etc/limer/clients-ca.pem
        }
    }
    reverse_proxy 10.0.0.2:8080 {
        tls_client_auth /etc/limer/limer-client.pem /etc/limer/limer-client.key
    }
}
```

`client_auth` asks the client for a certificate. `request` accepts any (or
none); `require` demands one but does not verify it; `verify_if_given`
verifies a presented certificate against `trusted_ca_cert_file`;
`require_and_verify` demands and verifies one. The settings are per site, so
sites sharing a listener each enforce their own. What the client presented is
available as the `tls_client` matcher and the `{tls_client_*}` placeholders
(subject, issuer, serial, fingerprint, verified, present). `tls_client_auth`
makes limer.sh present a client certificate when proxying to an upstream.

### Traffic splitting and mirroring

```
# send 5% of users to a canary, the same users every time
app.example.com {
    route {
        match split 5 cookie session
        reverse_proxy canary.internal:8080
    }
    reverse_proxy stable.internal:8080 {
        mirror shadow.internal:8080 { sample 10 }   # copy 10% to a shadow pool
    }
}
```

`match split <pct> [<key-source> [name]]` matches a deterministic fraction
of requests. It hashes a key (the client IP by default, or a header, cookie,
query, json field, ...) so a given client always lands on the same side;
put the split route before the fallback to peel off a slice of traffic.
`mirror` inside a `reverse_proxy` sends a fire-and-forget copy of each
request (head and body) to another pool and discards the response, so a slow
or dead mirror never affects the client; `sample <pct>` limits the share
copied. Mirrored routes buffer the request body.

### Response caching

```
{ cache_capacity 256m }
static.example.com {
    encode gzip zstd
    cache {
        ttl 5m         # freshness to assume when the response gives none
        stale 30s      # serve stale this long while revalidating in the background
        max_object 8m  # do not cache bodies larger than this
    }
    reverse_proxy 10.0.0.2:8080
}
```

GET and HEAD responses are cached in memory per worker. Freshness comes from
the response (`s-maxage`, `max-age`, `Expires`) or, failing that, the
configured `ttl`; a response is not cached when it is `no-store`, `private`,
carries `Set-Cookie` or `Vary: *`, or answers an authorized request without
`public`. The identity body is stored once and framed and compressed per
client, so one entry serves gzip, br and plain clients. Hits carry `Age` and
`X-Cache: HIT`; a client's `If-None-Match`/`If-Modified-Since` against a
cached validator gets `304`. A stale entry is revalidated conditionally and a
`304` refreshes it in place; within the `stale` window the stale copy is
served at once (`X-Cache: STALE`) while a background request refreshes it.
Total size is bounded by `cache_capacity` (default 64 MiB) with LRU
eviction, and `/metrics` reports hits, misses, stores, evictions and size.
One variant per URL is kept: a request whose `Vary` headers differ from the
stored variant replaces it.

## Automatic HTTPS

A site whose address is a public hostname gets a certificate without any
TLS configuration:

1. limer.sh starts with a temporary self-signed certificate so the listener is
   up immediately, plus an http listener on `http_port` that redirects to
   https and answers ACME http-01 challenges.
2. A certificate manager process registers an ACME account (`email`),
   orders a certificate for all of the site's names, proves control over
   each (http-01 by default), stores `cert.pem` and `key.pem` under
   `<storage>/certs/<host>/`, and reloads the server.
3. It checks every hour and renews 30 days before expiry, or when the stored
   certificate no longer covers the site's names.

Requirements: port 80 reachable from the internet (or `http_port` mapped to
it), DNS pointing at the server, and a writable `storage` directory. Use
`acme_ca` to point at another CA (staging, or
[Pebble](https://github.com/letsencrypt/pebble) for tests, with
`acme_ca_root` for its certificate). `auto_https off` disables
certificate management; `auto_https disable_redirects` keeps it but drops
the http redirect.

Challenge types (`acme_challenge` in the global block):

| Challenge | Needs | Notes |
|---|---|---|
| `http-01` (default) | port 80 reachable | Answered by the http listener. |
| `tls-alpn-01` | port 443 reachable | Answered on the https listener itself with the `acme-tls/1` ALPN protocol; use it when port 80 is closed. |
| `dns-01` | `acme_dns_script` | limer.sh runs the script as `script present <domain> <txt-value>` before validation and `script cleanup <domain> <txt-value>` after, waits `acme_dns_propagation` (`30s`) in between, and the script creates or removes `_acme-challenge.<domain>` TXT records with your DNS provider's API. Required for wildcard names, which are always validated over dns-01 when a script is set. |

### HTTP/3

```
{
    http3
}

example.com {
    reverse_proxy 10.0.0.5:8080
}
```

With `http3` in the global block, every HTTPS listener also opens a UDP
socket on the same address and port and serves HTTP/3 over QUIC (RFC 9000,
9114) with the same certificates, including ACME and `tls internal`
certificates and renewals. HTTP/1.1 and HTTP/2 responses over TLS carry
`Alt-Svc: h3=":443"; ma=86400` so browsers switch on their next request.
Everything behind the listener is shared: routing, matchers, handlers,
proxying (upstreams stay HTTP/1.1 or HTTP/2), request-body streaming,
caching, compression, rate limits, `ip_guard`, canary probation and access
logs (the protocol shows as `HTTP/3`). Open UDP 443 in the firewall.

Each worker binds the UDP port with `SO_REUSEPORT`; the kernel hashes a
client's address to one worker, so all packets of a QUIC connection reach
the worker that owns it (connection migration is disabled for the same
reason). Reloads keep QUIC
connections open; removing a site's last HTTPS listener or turning `http3`
off closes its UDP socket after in-flight connections finish.

Limitations:

- When the set of worker processes changes (a crashed worker is replaced,
  `limer upgrade`, a change of `workers`), the kernel may hash a QUIC
  connection's packets to a different worker, which does not know it, and
  the client reconnects. Browsers retry such a request over a new
  connection or fall back to HTTP/2, so this shows up as a reconnect, not an
  error.
- No 0-RTT and no Retry tokens (address validation relies on QUIC's
  handshake limits and `ip_guard`); a client that changes address (a phone
  moving from Wi-Fi to mobile) reconnects instead of migrating.
- Client certificates (`tls client_auth`) are not requested over HTTP/3;
  sites that require them should leave `http3` off.

## Admin API

Enable with `admin <addr>` in the global block.

| Endpoint | Returns |
|---|---|
| `GET /health` | `{"status":"ok"}` |
| `GET /upstreams` | JSON: every pool, policy, hash key, and per-upstream health, in-flight requests, counters. |
| `GET /metrics` | Prometheus text format. |
| `GET /config` | The running Limerfile. |
| `POST /reload` | Reload the configuration from disk. |
| `POST /upstreams/<host:port>/drain` | Stop sending new requests to the upstream (in-flight ones finish). |
| `POST /upstreams/<host:port>/undrain` | Put it back into rotation. |
| `POST /upstreams/<host:port>/weight/<n>` | Change its weight at runtime. |
| `POST /drain` | Self-drain: stop sending new requests to the upstream(s) at the caller's own address (`?port=N` narrows it to one port). |
| `POST /undrain` | Self-undrain: put the caller's upstream(s) back into rotation. |
| `POST /scale_up` | Run the `scale_up` hook now (`202`), or `429` with `Retry-After` inside its cooldown. |
| `GET /overrides`, `DELETE /overrides` | List or clear the runtime overrides. |

Drain and weight overrides apply to every pool using that upstream address,
are persisted to `<storage>/overrides.conf` so they survive reloads and
restarts, and reach every worker. Remove them with `DELETE /overrides`.
With `workers > 1`, counters are per worker (each response names its worker).

`/drain` and `/undrain` are meant for backends shutting down gracefully: on
`SIGTERM` an app calls `curl -X POST http://<limer-admin>/drain`, finishes the
requests it already has, and exits; on start it calls `/undrain`. The
upstream is chosen by the caller's source IP, so a backend can only ever drain
itself — safe even on a shared management network. The admin listener must be
reachable from the backends for this (bind `admin` to a management address
rather than `127.0.0.1`, or run limer beside the app). Without the call, an
active health check (`health_uri`) that starts failing achieves the same, only
one `health_interval` later.

### Securing the admin API

Once backends can reach the admin listener to call the webhooks, they can
reach every other endpoint too. Give it a secret, a webhook rate limit and
bans:

```
{
    admin 10.0.0.1:2019 {
        secret {$LIMER_ADMIN_SECRET}   # at least 16 characters, e.g. `openssl rand -hex 24`
        rate 6/m          # webhook calls per caller address (default 6/m; `off` to disable)
        burst 3           # calls allowed back to back (default 3)
        max_failures 5    # wrong secrets and rate-limit hits before a ban (default 5; 0 = never ban)
        ban 15m           # ban length, and the window strikes are counted over (default 15m)
    }
}
```

- With a secret, every endpoint except `/health` requires
  `Authorization: Bearer <secret>`; a request without it, or with a wrong one,
  gets `401`. The comparison runs in constant time.
- The webhooks (`/drain`, `/undrain`, `/scale_up`) are rate limited per
  caller address with a token bucket; calls beyond it get `429` with
  `Retry-After`.
- Every wrong secret and every call over the rate is a strike. A caller that
  collects `max_failures` strikes within `ban` is refused with `403` (and
  `Retry-After`) for `ban`, even with the right secret, and the ban is logged.
  Other callers are unaffected.
- The counters live in each worker, so with `workers N` a caller can make up
  to `N` times as many attempts before every worker has banned it.

A backend then calls, for example:

```
curl -X POST -H "Authorization: Bearer $LIMER_ADMIN_SECRET" http://10.0.0.1:2019/drain
```

Keep the secret out of the Limerfile with `{$LIMER_ADMIN_SECRET}` (set it in
the systemd unit's `Environment=` or an `EnvironmentFile=`). `limer reload`,
`upgrade` and `stop` use signals, not the admin API, so they need no secret.
When `admin` listens beyond loopback without a secret, limer.sh logs a
warning at startup.

## Reloads, upgrades and rollback

| Signal | Command | Effect |
|---|---|---|
| `SIGHUP` | `limer reload` | Reload the Limerfile. Listeners are kept or added; sites and pools are swapped atomically; in-flight requests finish on the old config; a config that fails to parse or bind is rejected and logged. |
| `SIGUSR2` | `limer upgrade` | Replace the running binary with the one now on disk, with no downtime (see below). |
| `SIGTERM` / `SIGINT` | `limer stop` | Stop accepting, finish in-flight requests within `grace`, exit. |

`limer run` always starts a master process that supervises `workers` worker
processes (1 by default). The workers each own all listeners via
`SO_REUSEPORT` and serve the traffic; the master forwards signals, runs the
certificate manager and restarts a worker that dies. A restarted worker uses
the master's last-known-good configuration from memory, not the file on disk,
so a config that was edited into something broken cannot turn one crash into a
crash loop.

### Zero-downtime upgrades

Install the new binary over the old one (`make install` writes a new file and
renames it into place), then run `limer upgrade`:

1. The master runs `<new binary> validate` on the current config in a
   throwaway process. If that fails — a binary that will not start, or a config
   it cannot parse — nothing changes and the error is logged.
2. The master re-executes itself in place: **the pid stays the same**, so
   systemd, a container runtime or a pidfile-based supervisor keep tracking
   it. Its workers are not touched and keep serving.
3. The new image starts its own workers, which bind the same ports next to the
   old ones (`SO_REUSEPORT`), so no connection is refused at any point.
4. Once the new workers are up, the old ones drain and exit.

Connection by connection, nothing is dropped: in a test that sent a request
every few milliseconds through an upgrade, 1,489 of 1,489 succeeded and the
master pid did not change.

### Automatic rollback

`auto_rollback` judges every reload and upgrade on live traffic, and reverts
the ones that make responses fail.

```
{
    auto_rollback {
        canary 5%          # share of new connections that get the new config (default 5%)
        window 15s         # how long a new config or binary is on probation (default 15s)
        error_rate 30%     # 5xx share that triggers a revert (default 50%)
        min_requests 20    # don't judge on fewer responses than this (default 20)
    }
}
```

**Configs.** After a reload, the new config is on probation for `window`. It
runs as a canary: each worker keeps the previous config and gives the new one
only `canary` percent of new connections (`canary 100%` switches everything at
once). Workers count the responses of each config separately, and if the new
one reaches `error_rate` 5xx — and does worse than the previous one over the
same window — the master reverts: it starts fresh workers from the previous
config and drains the current ones, without dropping a connection. If the
window passes cleanly, the new config is committed and takes all traffic. A
config pointing at a dead backend, for example, is typically caught within a
second or two, and with the default canary only about one connection in
twenty sees it.

**Binaries.** With `auto_rollback` on, `limer upgrade` first saves the running
binary to `<storage>/limer.previous`. The new binary then runs as a canary next
to the old workers, which keep serving until the probation ends. If the new
workers' 5xx share reaches `error_rate`, or they crash twice, the master
re-executes the saved binary in place (same pid again) and drains the new
workers; otherwise the new binary is committed and the old workers drain.

**Nothing comes back on restart.** Whatever is rolled back is moved aside and
the known-good version is written back in its place, atomically: the rejected
Limerfile is kept as `Limerfile.rejected-<time>` and the rejected binary as
`limer.rejected-<time>`, so a `systemctl restart` or a reboot starts the
version that was actually working. With `auto_rollback` on, a config that
fails to parse when the master reloads it (a raw `SIGHUP` or `POST /reload`)
is quarantined the same way; `limer reload` already refuses such a file before
signalling. Only the main Limerfile is restored: a change inside an `import`ed
file is left for you to fix.

Some things to keep in mind:

- The decision needs traffic. With the canary at 5%, a quiet site may finish
  the window with fewer than `min_requests` canary responses; the new config is
  then committed on what was seen.
- Judgement happens once a second, so a broken config serves its canary share
  for a second or two before it is reverted.
- The protection in force is the known-good config's: a new config cannot
  switch its own rollback off. A reload during an upgrade's probation is
  ignored (try again once the upgrade is committed).
- During a binary canary the split follows the number of workers (old and new
  each own the same listeners), not the `canary` percentage.
- `auto_rollback` cannot help when the master itself crashes in a new binary;
  the validation step is the guard against that.

## Testing

On macOS the shell suites need GNU coreutils and sed (`brew install
coreutils gnu-sed`; the scripts find them), and the checks that need more
loopback addresses than `127.0.0.1` are skipped with a note unless you add
them (`sudo ifconfig lo0 alias 127.0.0.2 up`, likewise `.3` and `.5`).

`make check` runs fourteen suites; `make check-asan` runs them on a build
instrumented with AddressSanitizer and UndefinedBehaviorSanitizer. The
GitHub Actions workflow in `.github/workflows/ci.yml` runs both on every push.

| Target | What it covers |
|---|---|
| `make unit` | `tests/unit.c`: buffers, parsing helpers, CIDR matching, globbing, the HTTP head parsers (including every smuggling guard), the chunked decoder, the JSON path extractor, the Limerfile parser (site addresses, imports, snippets, every directive and ~60 rejected inputs), matchers and key extraction, and every balancing policy. |
| `make fuzz` | `tests/fuzz.c`: a mutation fuzzer over the HTTP parsers, chunked decoder, JSON extractor, form/cookie extraction and config parser with invariant checks; reproducible by seed. |
| `make integration` | `tests/run_tests.sh`: end-to-end proxying behaviour against Python backends: routing, hashing, weights, framing, keep-alive, pipelining, timeouts, retries, health checks, WebSocket upgrade, admin API, reload, graceful stop, TLS and multi-worker mode. |
| `make features` | `tests/run_features.sh`: virtual hosts, SNI, redirects, handlers, basic auth, logging, static files, compression, TLS to upstreams, HTTP/2, rate limiting, sticky sessions, the runtime admin API, gRPC over h2c/h2 upstreams and bidirectional streaming (needs `grpcio` and `grpcio-tools`; skipped otherwise), streaming request bodies, dynamic upstreams (a small test DNS server), mutual TLS, traffic splitting and mirroring, response caching, and reload. |
| `make acme` | `tests/run_acme.sh`: certificate issuance over http-01, tls-alpn-01 and dns-01 (wildcard), storage and renewal against Pebble and pebble-challtestsrv (skips when they are not installed). |
| `make security` | `tests/security_tests.py`: the black-box security suite described below. |
| `make ddos` | `tests/ddos_test.py`: the per-IP connection guard — concurrent-connection caps, the new-connection rate limit, automatic ban escalation, and `trusted_proxies` client-IP keying. |
| `make scale` | `tests/scale_test.py`: the `scale_up` hook fires on a request spike with its context, and the cooldown holds it to one run. |
| `make drain` | `tests/drain_test.py`: a backend drains and undrains itself through `POST /drain` / `/undrain`. |
| `make rollback` | `tests/rollback_test.py`: under continuous traffic, a healthy reload is committed after its canary probation, a reload to a dead backend is reverted with only the canary share affected, and the rejected (and an invalid) Limerfile is quarantined while the good one is restored. |
| `make binrollback` | `tests/binrollback_test.py`: builds a deliberately broken limer, then upgrades under traffic — a good binary is committed, the broken one is rolled back with the same pid, and the previous binary is restored at its install path. |
| `make h3` | `tests/h3_test.py`: HTTP/3 with the aioquic client — local and proxied responses, forwarded headers, path and query, small and 200 KB POST bodies, a 3 MiB response, 20 concurrent streams on one connection, a bodiless 204, `Alt-Svc` on HTTPS over TCP, HTTP/3 after a reload, and a graceful stop (skips when aioquic is not installed). |
| `make admin` | `tests/admin_test.py`: the admin secret (`401` without it, `/health` open), `POST /scale_up` and its cooldown, bans for wrong secrets and for webhook floods, ban expiry, self-drain with the secret, one hook run across two workers, and config validation (short secrets, the open-admin warning). |
| `make status` | `tests/status_test.py`: `retry_status` sends a request to the next upstream on 404 and 503 and replays a POST body, a 404 from every upstream passes through, and `redirect_on` turns it into a redirect. |

## Security

limer.sh sits in front of your application, so it is strict about HTTP framing
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
  listener; bind it to localhost or a management network, and give it a
  `secret` when backends reach it for the webhooks. Wrong secrets and
  webhook floods earn the caller a ban.
- **No software fingerprint**: limer does not advertise itself. Its own
  responses carry no `Server` header by default (`server_header <value>` sets
  one, e.g. `server_header nginx` to masquerade); proxied responses pass the
  upstream's `Server` through untouched. Default header values carry no
  product name — the sticky-session cookie is `lb`, not a limer-branded name.
- **Memory safety**: the suites run clean under AddressSanitizer,
  UndefinedBehaviorSanitizer and Valgrind, and the fuzzer runs on every CI
  build.

## Performance

`bench/run.sh` reproduces these numbers. It builds a minimal epoll backend
(`bench/backend.c`), starts two of them, and drives limer.sh with
[wrk](https://github.com/wg/wrk) (and h2load when installed) over loopback.
Measured on a 4-vCPU Linux VM with wrk using 2 threads, 8-second runs,
keep-alive on:

| Scenario | Requests/s | p50 | p99 |
|---|---|---|---|
| wrk to backend directly (no proxy) | 152,000 | 0.58 ms | 2.0 ms |
| limer.sh, 1 worker, GET round robin, 100 connections | 33,000 | 2.8 ms | 6.3 ms |
| limer.sh, 1 worker, POST with JSON match + payload hash | 34,000 | 2.7 ms | 5.6 ms |
| limer.sh, 1 worker, GET, 1000 connections | 27,000 | 36 ms | 66 ms |
| limer.sh, 4 workers, GET round robin, 100 connections | 102,000 | 0.80 ms | 4.3 ms |
| limer.sh, 4 workers, POST with JSON match + payload hash | 98,000 | 0.83 ms | 5.4 ms |
| limer.sh, 4 workers, GET, 1000 connections | 116,000 | 7.4 ms | 19 ms |

Over TLS with h2load (10 connections, 10 streams each): HTTP/2 serves about
22,000 req/s per worker and 61,000 req/s with 4 workers; HTTP/1.1 over TLS
about 27,000 req/s per worker.

### HTTP/3 vs HTTP/2 vs HTTP/1.1

`bench/protocols.sh` drives one worker with a `tls internal` site over each
protocol with h2load (HTTP/3 needs an h2load built with `--enable-http3`;
set `H2LOAD`). Measured on a 1-vCPU VM, 100,000 requests per run, best of 3;
h2load, the two backends and limer.sh share the one core:

| Shape | HTTP/1.1 over TLS | HTTP/2 | HTTP/3 |
|---|---|---|---|
| 10 connections × 1 in flight | 20,500 req/s, p99 0.76 ms | 14,399 req/s, p99 1.0 ms | 10,753 req/s, p99 1.6 ms |
| 10 connections × 10 in flight | (no multiplexing) | 17,470 req/s, p99 8.9 ms | 25,209 req/s, p99 6.8 ms |
| 100 connections × 1 in flight | 20,101 req/s, p99 7.6 ms | 13,986 req/s, p99 9.7 ms | 8,797 req/s, p99 16 ms |

Every request succeeded on every protocol. With several requests in flight
per connection HTTP/3 is the fastest, about 45% ahead of HTTP/2; one
request at a time it costs more, because each QUIC packet is encrypted
and acknowledged individually in user space (on both sides, and here the
client competes for the same core). Over loopback there is no packet loss,
which is where HTTP/3 gains most on real networks. limer.sh sizes its UDP
socket buffers at 4 MiB, beyond `net.core.rmem_max` when running as root,
so bursts from many connections are not dropped (with the kernel default
of 208 KB, the 100-connection run lost 92,000 datagrams and p99 rose to
100 ms).

### Compared with Caddy

`bench/run.sh` also benchmarks Caddy when a `caddy` binary is on the PATH,
using `bench/Caddyfile` (the same two backends, `lb_policy round_robin`,
and an enlarged upstream keep-alive pool so Caddy is not limited by its
default of 32 idle connections per host). Same VM, same wrk settings,
Caddy v2.10.0:

| Scenario | Caddy | limer.sh | Ratio |
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

### Compared with nginx and HAProxy

`bench/compare.sh` runs limer, nginx and HAProxy side by side on the same box:
the same two `bench/backend.c` backends, one worker process (or thread) per
proxy, keep-alive to the backends, no access logging, wrk with two threads,
each scenario repeated in rotating order with the best run kept. It uses only
loopback test ports and never starts the nginx or HAProxy system services, so
it is safe on a machine that serves something else.

On a 1-vCPU VM (Linux 6.8; nginx 1.24, HAProxy 2.8.16; best of 3, 10 s runs):

| Scenario | limer | nginx | HAProxy |
|---|---|---|---|
| GET, keep-alive, 100 connections | 25,402 req/s, p99 6.0 ms | 25,456 req/s, p99 5.3 ms | 25,131 req/s, p99 5.8 ms |
| GET, keep-alive, 1000 connections | 18,553 req/s, p99 97 ms | 17,531 req/s, p99 86 ms | 17,942 req/s, p99 67 ms |
| POST 120 B JSON, 100 connections | 24,449 req/s, p99 6.2 ms | 24,240 req/s, p99 6.3 ms | 24,901 req/s, p99 5.7 ms |
| GET, new connection per request | 10,256 req/s, p99 12.4 ms | 10,064 req/s, p99 13.2 ms | 10,550 req/s, p99 11.8 ms |

The three are level: limer is ahead at 1000 connections, nginx by a hair on
keep-alive GETs, HAProxy on POSTs, tail latency at 1000 connections and the fresh-connection
path, and none of the gaps exceeds about 6% in throughput. On one core the load
generator and the backends compete with the proxy for the CPU, so this
measures relative efficiency, not the ceiling; repeat it on a multi-core
machine with `workers` / `worker_processes` / `nbthread` raised to compare
scaling.

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
(plus payload hashing, which Caddy lacks), sticky sessions, rate limiting,
response caching, streaming request bodies, dynamic upstreams (DNS A/SRV),
traffic splitting and request mirroring, mutual TLS, site addresses and
virtual hosts, automatic HTTPS (http-01, tls-alpn-01, dns-01 with
wildcards), HTTP/3, HTTP/2 on both sides including gRPC passthrough, static files,
compression, the common handler directives, Caddyfile-style config with
imports and snippets, reloads, metrics, a runtime admin API for draining and
weights, multi-process workers.

Not there: built-in DNS provider modules (dns-01 goes through a
script), on-demand TLS, templates, FastCGI, the JSON config API and the
plugin ecosystem.

## Layout

```
src/limer.h    shared types
src/main.c     CLI, master/worker supervision
src/config.c   Limerfile tokenizer, imports/snippets, block parser, validation
src/proxy.c    event loop, client/upstream state machines, files, health checks, admin API, reload
src/epoll_kqueue.h  the epoll calls the event loop uses, on kqueue (macOS)
src/compat.h   socket flags, accept4, memrchr on macOS
src/h2.inc     HTTP/2 sessions and streams (nghttp2), included by proxy.c
src/h3.inc     HTTP/3 over QUIC (ngtcp2, nghttp3, GnuTLS), included by proxy.c
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
