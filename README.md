# limer.sh

**An ultra-fast HTTP server and load balancer, written in C, that routes on
what's *inside* the request.**

Most proxies only see the method and the path. limer.sh routes and balances on
JSON fields, form fields, body regexes, headers, cookies, the query, the path,
or the client address. It works like [Caddy](https://caddyserver.com): one
binary, a readable `Limerfile`, automatic HTTPS, HTTP/2 and gRPC, zero-downtime
reloads and an admin API.

🌐 **[limer.sh](https://limer.sh)** &nbsp;·&nbsp; 📖 **[User guide](USERGUIDE.md)**

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

    # Everything else: least-connections with active health checks
    reverse_proxy 10.0.0.10:8080 10.0.0.11:8080 10.0.0.12:8080 {
        lb_policy least_conn
        health_uri /healthz
    }
}
```

That site gets a certificate from Let's Encrypt automatically, serves HTTPS
with HTTP/2 and HTTP/1.1, and redirects plain HTTP to HTTPS.

## Why limer.sh

- **Payload-based routing & balancing** — pick a handler or an upstream from
  the request body, with weighted rendezvous hashing so a key always lands on
  the same backend and only a departed upstream's keys get remapped.
- **A full edge in one binary** — reverse proxy with health checks, sticky
  sessions, rate limiting, response caching, dynamic upstreams (DNS A/SRV),
  traffic splitting and mirroring, mutual TLS, static files and compression.
- **Automatic HTTPS** — Let's Encrypt over http-01, tls-alpn-01 or dns-01
  (wildcards included); `tls internal` for local dev.
- **HTTP/2 and gRPC** both sides, trailers intact, including bidirectional
  streaming.
- **About 3–5× Caddy** on the HTTP/1.1 reverse-proxy path (see
  [benchmarks](USERGUIDE.md#performance)).

## Quick start

```sh
git clone https://github.com/limer-sh/limer
cd limer && make            # optional libs (OpenSSL, nghttp2, zstd, brotli) auto-detected
sudo make install           # installs to /usr/local/bin

limer run -c Limerfile      # run in the foreground
limer validate -c Limerfile # parse, resolve upstreams, load certificates
limer reload                # zero-downtime reload
```

Try payload routing locally with the bundled test backend:

```sh
python3 tests/backend.py 9001 shard-a &
python3 tests/backend.py 9002 shard-b &
python3 tests/backend.py 9003 shard-c &
./limer run -c examples/payload-routing.Limerfile
curl -X POST localhost:8080/echo -d '{"tenant":"acme","event":"signup"}'
```

## Documentation

The full reference — every directive, matcher, load-balancing policy, the
admin API, automatic HTTPS, security model and benchmarks — lives in
**[USERGUIDE.md](USERGUIDE.md)**.

## License

[MIT](LICENSE) © restimguay
