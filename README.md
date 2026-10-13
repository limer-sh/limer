# Limer

Limer is a small, fast HTTP load balancer written in C with **payload-based
request distribution**. It routes and balances requests on what is *inside*
them: JSON fields, form fields, regexes over the body, headers, cookies, the
path, or the client address. Configuration and day-to-day operation follow the
conventions of [Caddy](https://caddyserver.com): a single binary, a readable
`Limerfile`, `limer run` / `limer validate` / `limer reload` / `limer stop`,
zero-downtime config reloads, and an admin API.

```
{
    admin 127.0.0.1:2019
}

:8080 {
    # Same customer -> same upstream, chosen by a field in the JSON body
    route orders {
        match method POST
        match json type == order refund
        to 10.0.1.10:8080 10.0.1.11:8080
        lb_policy hash json customer.id
    }

    # Everything else: least-connections over three backends with health checks
    reverse_proxy 10.0.0.10:8080 10.0.0.11:8080 10.0.0.12:8080 {
        lb_policy least_conn
        health_uri /healthz
    }
}
```

## Features

- **Payload-based routing**: pick a pool by matching JSON fields (dot paths,
  `items[0].sku`), form fields, body regexes, headers, cookies, query
  parameters, method, path (globs or regex), host, or client IP/CIDR.
  Matchers in a route are AND-ed; values on one matcher are OR-ed. Operators:
  `==` `!=` `~` (regex) `!~` `>` `<` `>=` `<=` `^=` (prefix) `*=` (contains)
  `exists` `missing`, plus `match not ...`.
- **Payload-based balancing**: `lb_policy hash json <path>` (or `form`,
  `body`, `header`, `cookie`, `query`, `path`, `uri`, `client_ip`) uses
  weighted rendezvous hashing so a key always lands on the same upstream and
  only the keys of an upstream that goes away get remapped.
- Classic policies: `round_robin` (smooth weighted), `least_conn`, `random`,
  `first` (failover), `ip_hash`, `uri_hash`; per-upstream `weight=N`.
- **Health**: active HTTP health checks and passive ejection (`max_fails` /
  `fail_timeout`, optional `unhealthy_status 5xx`); automatic retries on other
  upstreams when a connection fails before a response is seen.
- **HTTP/1.1 done properly**: keep-alive on both sides with an upstream
  connection pool, pipelining, chunked request and response bodies,
  `Expect: 100-continue`, HEAD/204/304 framing, close-delimited responses,
  HTTP/1.0 clients, WebSocket / `Upgrade` tunnelling, request-smuggling
  guards, bounded buffering with backpressure for large responses.
- Caddy-style forwarding headers (`X-Forwarded-For/Proto/Host`, `X-Real-IP`),
  `header_up` / `header_down` with placeholders, `respond` and `redir`
  handlers.
- **Operations**: `limer validate`, hot reload on `SIGHUP` / `limer reload` /
  `POST /reload` (bad configs are rejected and the old one keeps running),
  graceful shutdown with a grace period, multi-process `workers` with
  `SO_REUSEPORT`, pidfile, access logs, admin API with JSON upstream status and
  Prometheus metrics.
- Optional **TLS termination** (OpenSSL) for `https://` listeners.
- No dependencies beyond libc (and OpenSSL if you want TLS). Linux (epoll).

## Building

```
make            # builds ./limer; TLS is enabled when OpenSSL is found
make TLS=0      # force a build without OpenSSL
make check      # unit tests, parser fuzzing, integration and security suites
make install    # installs to /usr/local/bin
```

## Running

```
limer run                     # uses ./Limerfile or /etc/limer/Limerfile
limer run -c path/Limerfile   # explicit config
limer validate -c Limerfile   # parse, resolve upstreams, load certificates
limer reload                  # SIGHUP the running instance (needs `pidfile`)
limer stop                    # graceful SIGTERM
limer version
```

`limer run` stays in the foreground and logs to stderr (access log to stdout),
which is what you want under systemd, Docker, or a supervisor.

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

```
# optional global options, must come first
{
    workers 4                 # or "auto"; default 1
    admin 127.0.0.1:2019      # admin API listener; "off" to disable
    log_level info            # debug | info | warn | error
    max_connections auto      # per worker; auto = half the descriptor limit
    pidfile /run/limer.pid
    grace 10s                 # drain time on shutdown
}

<addresses> {                 # ":8080", "127.0.0.1:8080", "[::1]:8080", "https://:8443"
    <server directives>
}
```

Several addresses can share one block (`:8080, :8081 {`). Multiple server
blocks are allowed.

### Global options

| Option | Default | Meaning |
|---|---|---|
| `workers <n|auto>` | `1` | Worker processes sharing the listeners. |
| `admin <addr|off>` | off | Admin API listener. |
| `log_level <level>` | `info` | `debug`, `info`, `warn` or `error`. |
| `max_connections <n|auto>` | `auto` | Client connection cap per worker; `auto` derives it from the descriptor limit. |
| `pidfile <path>` | none | Written on start; used by `limer reload` and `limer stop`. |
| `grace <dur>` | `10s` | Time allowed for in-flight requests on shutdown. |

### Server directives

| Directive | Meaning |
|---|---|
| `max_body <size>` | Largest request body accepted (`8m` default). Bodies are buffered so routing can inspect them; larger requests get `413`. |
| `read_timeout <dur>` | Time to receive a complete request (`30s`). |
| `idle_timeout <dur>` | Keep-alive idle time (`2m`). |
| `log` | Enable the access log (stdout). |
| `tls <cert.pem> <key.pem>` | Terminate TLS on this block's listeners. |
| `respond [status] [body]` | Catch-all static response. |
| `reverse_proxy [upstreams...] [{ ... }]` | Catch-all proxy pool. |
| `route [name] { ... }` | Matchers plus one handler (`to`, `respond`, or `redir`). |

Routes and `reverse_proxy` blocks are evaluated in order; the first match
wins. Requests that match nothing get `404`.

### Matchers (inside `route`)

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

### Handler directives (inside `route` and `reverse_proxy { }`)

| Directive | Default | Meaning |
|---|---|---|
| `to <host:port> [weight=N] ...` | | Upstreams. `http://` prefixes are accepted. Repeatable. |
| `lb_policy <policy> [args]` | `round_robin` | See below. |
| `lb_retries <n>` | `2` | Extra upstreams to try when a connection fails before any response byte. |
| `max_fails <n>` / `fail_timeout <dur>` | `3` / `10s` | Passive health: eject an upstream after `n` consecutive failures for `fail_timeout`. `max_fails 0` disables. |
| `unhealthy_status 5xx` | off | Count 5xx responses as passive failures. |
| `health_uri <path>` | off | Active health check URL. |
| `health_interval` / `health_timeout` | `10s` / `5s` | Check cadence and timeout. |
| `health_status <code>` | any 2xx/3xx | Expected status. |
| `health_host <host>` | upstream address | `Host` header for checks. |
| `connect_timeout` / `response_timeout` | `5s` / `60s` | Dial timeout and time to first response byte (`504` on expiry). |
| `keepalive_idle <n>` | `256` | Idle upstream connections to pool per upstream (`0` disables pooling). |
| `keepalive_timeout <dur>` | `60s` | How long pooled connections may idle. |
| `header_up [+|-]Name [value]` | | Set, add (`+`), or delete (`-`) request headers sent upstream. |
| `header_down [+|-]Name [value]` | | Same for response headers. |
| `preserve_host on|off` | `on` | Pass the client's `Host` through (off: use the upstream address). |
| `respond [status] [body]` | | Static response (route handler). |
| `redir <location> [code]` | `302` | Redirect (route handler); placeholders allowed. |

Header values and redirect targets may use placeholders: `{remote_ip}`,
`{host}`, `{path}`, `{query}`, `{uri}`, `{method}`, `{scheme}`, `{route}`,
`{upstream_hostport}`, `{upstream_host}`, `{header.Name}`.

### Load balancing policies

| Policy | Behaviour |
|---|---|
| `round_robin` | Smooth weighted round robin. |
| `least_conn` | Fewest in-flight requests (weighted), random tie-break. |
| `random` | Weighted random. |
| `first` | First healthy upstream in order (active/passive failover). |
| `ip_hash` | Hash of the client IP. |
| `uri_hash` | Hash of the request URI. |
| `hash <source> [name]` | Rendezvous hash of an extracted key: `hash json customer.id`, `hash form cart_id`, `hash header X-Session`, `hash cookie sid`, `hash query user`, `hash body`, `hash path`, `hash client_ip`. `payload` is an alias for `hash`. |

When the hash key is missing from a request, that request falls back to round
robin. Unhealthy upstreams are skipped, so their keys spill over to the
next-best upstream and return when the upstream recovers.

Limer always forwards `X-Forwarded-For` (appending), `X-Forwarded-Proto`,
`X-Forwarded-Host` and `X-Real-IP`, strips hop-by-hop headers, and keeps
`Upgrade` requests working (WebSockets are tunnelled after a `101`).

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
| `SIGHUP` | Reload the Limerfile. Listeners are kept or added; routes and pools are swapped atomically; in-flight requests finish on the old config; a config that fails to parse or bind is rejected and logged. |
| `SIGTERM` / `SIGINT` | Stop accepting, finish in-flight requests within `grace`, exit. |

With `workers N`, a master process supervises `N` workers that each own all
listeners via `SO_REUSEPORT`, restarts crashed workers, and forwards `SIGHUP`
and `SIGTERM`.

## Testing

`make check` runs four suites; `make check-asan` runs the same suites on a
build instrumented with AddressSanitizer and UndefinedBehaviorSanitizer. The
GitHub Actions workflow in `.github/workflows/ci.yml` runs both on every push.

| Target | What it covers |
|---|---|
| `make unit` | `tests/unit.c`: buffers, duration/size/address parsing, CIDR matching, globbing, the request and response head parsers (including every smuggling guard), the chunked decoder fed byte by byte, the JSON path extractor (escapes, surrogates, duplicates, nesting limits), the Limerfile parser (structure and ~40 rejected inputs), matchers and key extraction, and every balancing policy (weights, stickiness, minimal key movement, passive failure accounting). |
| `make fuzz` | `tests/fuzz.c`: a mutation fuzzer that drives the HTTP parsers, chunked decoder, JSON extractor, form/cookie extraction and config parser with mutated seeds and checks their invariants. `FUZZ_ITERS=N` and a seed argument make runs reproducible. Two crashes were found and fixed this way. |
| `make integration` | `tests/run_tests.sh`: end-to-end behaviour against Python backends: routing, hashing, weights, framing, keep-alive, pipelining, timeouts, retries, health checks, WebSocket upgrade, admin API, reload, graceful stop, TLS and multi-worker mode. |
| `make security` | `tests/security_tests.py`: the black-box security suite described below. |

## Security

Limer sits in front of your application, so it is strict about HTTP framing
and defensive about everything a client or upstream can send. The security
suite (`make security`) exercises each of these against a running instance,
including a scripted hostile upstream and a wire-level fuzz round, and
verifies the proxy keeps serving after every attack.

- **Request smuggling**: a message with both `Content-Length` and
  `Transfer-Encoding`, conflicting `Content-Length` values, any transfer
  coding other than exactly `chunked`, whitespace before a header colon,
  obsolete line folding, or a non-numeric length is rejected with `400` and
  the connection is closed, so nothing after it can be interpreted as a
  second request. Bodies are always re-framed with a fresh `Content-Length`
  upstream; trailers are dropped.
- **Malformed input**: NUL bytes and control characters in heads, invalid
  header names, HTTP/0.9 or HTTP/2 request lines and binary garbage are
  rejected. Absolute-form targets are normalised to origin-form before being
  sent upstream.
- **Limits**: request heads above 64 KiB (`431`), more than 128 headers,
  bodies above `max_body` (`413`, checked before buffering and again while
  decoding chunks), chunk sizes that overflow, slow clients (`408` after
  `read_timeout`), silent keep-alive connections (`idle_timeout`),
  `max_connections` per worker, and accept backoff when the process runs out
  of file descriptors. JSON nesting is capped so a hostile body cannot
  exhaust the stack; response bodies are streamed with backpressure instead
  of buffered.
- **Header hygiene**: hop-by-hop headers (`Connection`, `Keep-Alive`, `TE`,
  `Trailer`, `Transfer-Encoding`, `Upgrade`, `Proxy-*`) and any header
  nominated by `Connection` are stripped in both directions. `X-Forwarded-For`
  is appended to, while `X-Real-IP`, `X-Forwarded-Proto` and
  `X-Forwarded-Host` are always set by the proxy, so clients cannot spoof
  them. Header values can never contain CR or LF, so placeholders cannot
  split responses.
- **Hostile upstreams**: responses with conflicting framing, invalid chunk
  sizes, NUL bytes, oversized heads, bogus status lines, unsolicited `101`s
  or a closed connection become a clean `502`. A bodiless response that
  still advertises a body is never pooled, so stray bytes cannot poison the
  next request on that connection.
- **Admin API isolation**: the admin endpoints exist only on the `admin`
  listener. Bind it to localhost or a management network; anyone who can
  reach it can read the configuration and trigger reloads.
- **Memory safety**: the suites run clean under AddressSanitizer,
  UndefinedBehaviorSanitizer and Valgrind, and the fuzzer runs on every CI
  build.

Reports of security issues are welcome as GitHub issues on this repository.

## Performance

`bench/run.sh` reproduces these numbers. It builds a minimal epoll backend
(`bench/backend.c`), starts two of them, and drives Limer with
[wrk](https://github.com/wg/wrk) over loopback. Measured on a 4-vCPU Linux
VM with wrk using 2 threads, 8-second runs, keep-alive on:

| Scenario | Requests/s | p50 | p99 |
|---|---|---|---|
| wrk to backend directly (no proxy) | 152,000 | 0.58 ms | 2.0 ms |
| Limer, 1 worker, GET round robin, 100 connections | 33,000 | 2.8 ms | 6.3 ms |
| Limer, 1 worker, POST with JSON match + payload hash | 34,000 | 2.7 ms | 5.6 ms |
| Limer, 1 worker, GET, 1000 connections | 27,000 | 36 ms | 66 ms |
| Limer, 4 workers, GET round robin, 100 connections | 102,000 | 0.80 ms | 4.3 ms |
| Limer, 4 workers, POST with JSON match + payload hash | 98,000 | 0.83 ms | 5.4 ms |
| Limer, 4 workers, GET, 1000 connections | 116,000 | 7.4 ms | 19 ms |

Observations:

- Inspecting the body (JSON field match plus rendezvous hashing on a JSON
  path) costs about the same as plain round robin: matching and hashing are
  a few microseconds per request.
- A proxied request costs exactly four syscalls in Limer (read and write on
  each side) plus a share of one `epoll_wait`; user-space CPU is roughly
  2 µs per request. The single-worker ceiling is kernel loopback TCP cost,
  which is why workers scale close to linearly (`workers auto`).
- Keep `keepalive_idle` at or above your expected concurrency per upstream.
  Reconnecting for every request roughly halves throughput and multiplies
  tail latency; the default is 256 idle connections per upstream.

### Connection capacity

Each client connection costs one file descriptor and about 3 KB of memory
while idle (5 KB once it has served a request, since small buffers are
retained). Each request in flight additionally needs one upstream
descriptor. At startup every worker raises its descriptor limit to the hard
limit and, unless `max_connections` is set, caps client connections at half
of it so an accepted connection can always reach an upstream; connections
beyond the cap are closed immediately rather than queued. Measured on the
same VM (hard limit 20,000 descriptors):

| Test | Result |
|---|---|
| 18,000 keep-alive connections opened, one request each (in waves of 1,000) | all served; 55 MB idle, 90 MB after serving |
| New requests while 18,000 connections sit idle | p50 0.14 ms, p99 0.75 ms |
| 9,900 requests in flight simultaneously on one worker | all served in 1.1 s |
| 12,000 connections against a cap of 9,968 | 9,968 served, 2,032 closed at accept |

Timeouts are scanned every 250 ms in O(connections), which is negligible
at these sizes. With a typical production limit of 1,048,576 descriptors,
one worker can hold roughly 500,000 connections in about 2.5 GB; use
`workers auto` to spread them over cores.

## Layout

```
src/limer.h    shared types
src/main.c     CLI, master/worker supervision
src/config.c   Limerfile tokenizer, block parser, validation
src/proxy.c    epoll loop, client/upstream state machines, health checks, admin API, reload
src/http.c     HTTP/1.x head parsing, chunked coding
src/json.c     JSON path extraction
src/match.c    matchers and key extraction
src/balance.c  balancing policies, passive health accounting
src/tls.c      OpenSSL glue
tests/         unit tests, parser fuzzer, integration and security suites, test backend
bench/         wrk-based benchmark (run.sh), minimal C backend, benchmark Limerfile
.github/       CI workflow (normal and sanitized builds)
examples/      annotated Limerfiles
```

## Limitations

- HTTP/1.x only on both sides (no HTTP/2, no TLS to upstreams).
- TLS uses certificates you provide; there is no ACME client.
- Request bodies are buffered up to `max_body`; responses are streamed.
