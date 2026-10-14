# limer.sh use cases

limer.sh is a plain reverse proxy when you want one, and a content-aware one
when you need it. These are shapes it fits particularly well, each with a
runnable `Limerfile`. See [USERGUIDE.md](USERGUIDE.md) for every directive.

- [Stateful sharding — pin a key to a backend](#stateful-sharding)
- [Content-based routing — route on the body](#content-based-routing)
- [API edge — HTTPS, rate limits, DoS mitigation](#api-edge)
- [gRPC load balancing](#grpc-load-balancing)
- [Canary releases and traffic mirroring](#canary-and-mirroring)
- [Drop-in nginx / Caddy replacement](#drop-in-edge)
- [Multi-tenant fan-out with failover](#multi-tenant-failover)

---

## Stateful sharding

**Problem.** Your backends keep per-customer state — an in-memory cache, a
session store, a shard of data — so every request for a given customer must
reach the same node, and when a node leaves only *its* customers should move.

**limer.sh.** Weighted rendezvous hashing on a field inside the request body.

```
api.example.com {
    reverse_proxy node-1:8080 node-2:8080 node-3:8080 {
        lb_policy hash json customer.id
        health_uri /healthz
    }
}
```

A request with `{"customer":{"id":"acme"},...}` always lands on the same node
while it is healthy. Requests missing the field fall back to round robin. Hash
on a header, cookie, query or form field instead with `hash header X-Tenant`,
`hash cookie sid`, and so on.

---

## Content-based routing

**Problem.** Different requests to the same URL need different handling:
refunds go to a finance service, premium tenants to a bigger pool, a new API
version to the new backend — and the distinction is in the body, not the path.

**limer.sh.** Match on JSON/form/body fields and pick a pool per route.

```
api.example.com {
    route refunds {
        match method POST
        match json type == refund chargeback
        reverse_proxy finance-1:8080 finance-2:8080
    }

    route premium {
        match json plan == enterprise
        reverse_proxy big-1:8080 big-2:8080 {
            lb_policy least_conn
        }
    }

    # everyone else
    reverse_proxy std-1:8080 std-2:8080
}
```

Matchers in a route are AND-ed, values are OR-ed, and the first matching route
wins. Operators include `==` `!=` `~` (regex) `>` `<` `^=` `*=` `exists`.

---

## API edge

**Problem.** You want one thing in front of your API that terminates TLS,
throttles abusive clients and absorbs application-layer floods — without
standing up a cert pipeline, a sidecar and a separate WAF.

**limer.sh.** Automatic HTTPS, per-key rate limiting and a per-IP connection
guard, in one binary.

```
{
    trusted_proxies 10.0.0.0/8          # behind a CDN/LB: see the real client
    ip_guard {
        max_conns_per_ip 200            # cap concurrent connections per IP
        conn_rate 100r/s                # and the new-connection rate
        ban_threshold 10                # auto-ban repeat offenders
        ban_duration 5m
    }
}

api.example.com {
    rate_limit {
        key {header.X-Api-Key}          # per API key
        rate 100r/s
        burst 200
    }
    reverse_proxy app-1:8080 app-2:8080 {
        lb_policy least_conn
        health_uri /healthz
    }
}
```

`api.example.com` gets a Let's Encrypt certificate automatically and redirects
HTTP to HTTPS. Rate-limited clients get `429` with `Retry-After`; a client that
trips the limits enough times is banned at the edge. This is L7 mitigation —
put network-layer DDoS scrubbing in front for volumetric attacks.

---

## gRPC load balancing

**Problem.** You need to spread gRPC calls across a pool and keep trailers
(`grpc-status`, trailing metadata) intact, including streaming calls.

**limer.sh.** HTTP/2 to the upstreams over `h2c://` (cleartext) or `h2://`
(TLS), multiplexed on one session per upstream, trailers preserved.

```
grpc.example.com {
    reverse_proxy h2c://10.0.0.5:50051 h2c://10.0.0.6:50051 {
        lb_policy round_robin
    }
}
```

Clients can use TLS with ALPN or plain HTTP/2 with prior knowledge. Unary,
server-streaming, client-streaming and bidirectional calls all pass through;
a route that does not read the body forwards frames as they arrive. For
h2-only backends rely on passive health (active checks are HTTP/1.1).

---

## Canary and mirroring

**Problem.** You want to send a small, stable slice of users to a new build
and shadow real traffic to a staging pool to test it under load — without
affecting anyone.

**limer.sh.** A deterministic, sticky split plus fire-and-forget mirroring.

```
app.example.com {
    # 5% of users to the canary, the same users every time
    route {
        match split 5 cookie session
        reverse_proxy canary.internal:8080
    }

    # everyone else — and shadow 10% of it to staging
    reverse_proxy stable-1:8080 stable-2:8080 {
        mirror staging.internal:8080 { sample 10 }
    }
}
```

`match split` hashes a key (here the `session` cookie) so a given user always
lands on the same side. `mirror` copies the request to another pool and
discards the reply, so a slow or dead mirror never touches the client.

---

## Drop-in edge

**Problem.** You just need a fast static server and reverse proxy with TLS and
virtual hosts — a lighter, quicker stand-in for nginx or Caddy.

**limer.sh.** A familiar Caddy-style config, one binary, ~3–5× the throughput.

```
example.com, www.example.com {
    encode gzip zstd br

    handle_path /static/* {
        root /srv/www
        file_server
    }

    reverse_proxy app:8080
}

old.example.com {
    redir https://example.com{uri} permanent
}
```

Automatic certificates for every hostname, HTTP/2, compression negotiated per
client, byte ranges and conditional requests on static files, and zero-downtime
reloads with `limer reload`.

---

## Multi-tenant failover

**Problem.** Primary and standby pools per region, and you want traffic to a
standby only when the primary is unhealthy.

**limer.sh.** The `first` policy with active health checks.

```
eu.example.com {
    reverse_proxy eu-primary:8080 eu-standby:8080 {
        lb_policy first            # standby only when primary is down
        health_uri /healthz
        health_interval 5s
        max_fails 3
        fail_timeout 10s
    }
}
```

`first` always prefers the earliest healthy upstream, so the standby takes over
on failure and hands back when the primary recovers. Pools can also be built
from DNS with `dynamic a` / `dynamic srv` and re-resolved on an interval.
