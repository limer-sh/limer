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
make check      # integration tests (needs python3 and curl)
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
    pidfile /run/limer.pid
    grace 10s                 # drain time on shutdown
}

<addresses> {                 # ":8080", "127.0.0.1:8080", "[::1]:8080", "https://:8443"
    <server directives>
}
```

Several addresses can share one block (`:8080, :8081 {`). Multiple server
blocks are allowed.

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
| `keepalive_idle <n>` | `32` | Idle upstream connections to pool per upstream (`0` disables pooling). |
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
tests/         integration suite (`make check`) and a test backend
examples/      annotated Limerfiles
```

## Limitations

- HTTP/1.x only on both sides (no HTTP/2, no TLS to upstreams).
- TLS uses certificates you provide; there is no ACME client.
- Request bodies are buffered up to `max_body`; responses are streamed.
