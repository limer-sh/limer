# Feedback 1: the response cache, tested in front of Quillo (2026-11-07)

Found during Quillo's auto-CDN study (`feedback/reports/FEEDBACK59.md` in quillo-app1), which put
Limer in front of a Quillo server as a shared cache, then looked closer with a test origin.

Tested on macOS with `limer.sh 0.1.0 (tls, http/2)`, built from 4f80ddb (no source is newer than
the binary), one worker, plain HTTP, in front of a small test origin (at the end of this file) and
Quillo 0.7.0. No Limer source was changed. The VPS was not touched, so **it is not known whether a
production site uses `cache`**. Check `/etc/limer/Limerfile` first: problem 1 would hit any site
with a `cache` block whose origin compresses.

Nine problems, most severe first. All are open.

| # | Problem | What a visitor gets |
|---|---|---|
| 1 | A kept gzip answer loses its `Content-Encoding`, or is gzipped twice | **Garbage, from the second request on** |
| 2 | `private` or `Vary: Cookie` on a second header line is not seen | **Another visitor's answer** |
| 3 | Two sites on one host name share entries, as the key has no port | **Another site's answer** |
| 4 | `ttl` keeps answers that say nothing, and some that say "already expired" | **Another visitor's page** |
| 5 | `no-cache` is asked about once, then reused for 60 seconds or `ttl` | An old file |
| 6 | `stale` serves what `must-revalidate` forbids | An old file |
| 7 | Different `Accept-Encoding` strings push each other out | A working site with no cache: 0 hits in 60 |
| 8 | Nothing can remove an entry: no purge, and a reload keeps them | A bad entry stays until a restart |
| 9 | The guide's one-line `{ cache_capacity 256m }` is refused | Nothing: the example does not load |

Problems 1 to 3 need fixing before Limer is used as a cache in front of anything that compresses,
sets `Cache-Control` per visitor, or shares a host name. Quillo compresses every text answer from
1 KB up, so it is hit by problem 1 on nearly every page.

## 1. A kept gzip answer reaches the next visitor as garbage

### What happened

Quillo's runtime file, 137 KB plain, through a site with `cache { ttl 5m }`:

| Request | `X-Cache` | `Content-Encoding` | Bytes | Result |
|---|---|---|---|---|
| Client taking gzip, first | MISS | gzip | 38,523 | readable |
| Client taking gzip, second | HIT | **none** | 38,523 | **raw gzip, with no header saying so** |
| Client taking gzip, on a site with `encode gzip` | HIT | gzip | 38,556 | **gzipped twice: still gzip after one decode** |
| Plain client | MISS | none | 136,966 | readable |

A page goes the same way. Through Limer, `curl --compressed` got a readable Quillo page the first
time, and binary with `X-Cache: HIT` and no `Content-Encoding` the second. So the first visitor
fills the cache and everyone after them with the same `Accept-Encoding` gets bytes they cannot
read. Not tried in a browser: `curl` shows the bytes it would be given.

The `encode gzip` row reached a kept entry through problem 3 (another site's entry on the same
host). The test origin's answer was too small for `encode` to touch, and came back with no header,
as in the second row. So a single site with `encode` and a large answer was not run by itself. The
code path is the same.

### Cause

`cache_consider_response` leaves `Content-Encoding` out of what it stores (`src/proxy.c:3233`), and
`conn_serve_cached` leaves it out when serving (`src/proxy.c:3049`, "framing/encoding are recomputed
for this client"). Both assume the stored body is plain, as the guide says: "The identity body is
stored once and framed and compressed per client".

But the client's `Accept-Encoding` goes to the upstream as it came, so an origin that compresses
answers with gzip, and those bytes are what is stored.

The test at `tests/run_features.sh:786-791` fills the cache with a plain `curl`, so it stores a
plain body and passes. Nothing tests a gzip client first, or an origin that compresses.

### Fix to make

1. **Now, one condition:** in `cache_consider_response`, return when the answer has a
   `Content-Encoding` other than `identity`. Such answers are then not kept, which is safe.
2. **Then what the guide promises:** on a request that may be kept, ask the upstream for a plain
   body (drop `Accept-Encoding`) and compress per client. That needs `encode` on the site, or
   clients lose compression. Without `encode`, store the `Content-Encoding` with the entry and
   match on it. This also fixes problem 7.

A test: gzip client first, against an origin that compresses, then a gzip client and a plain
client, each decoded and compared with the original.

## 2. `private` or `Vary: Cookie` on a second header line is not seen

### What happened

The same answer, sent to Ana and then to Bob:

| The origin sends | Ana gets | Bob gets |
|---|---|---|
| `Cache-Control: max-age=60`, then `Cache-Control: private` | for ana | **for ana**, HIT |
| `Vary: Accept-Encoding`, then `Vary: Cookie` (with `public, max-age=60`) | for ana | **for ana**, HIT |
| `Vary: Accept-Encoding, Cookie`, one line | for ana | for bob, MISS |

Repeating a field on several lines is the same as one line with commas (RFC 9110, section 5.3).
Quillo sends `Vary` this way: `Vary: Cookie` and `vary: accept-encoding` as two lines. It is safe
today only because `Cookie` happens to come first.

### Cause

`http_hdr_get` returns the first header of a name (`src/http.c:39`). `cache_consider_response`,
`response_declared_ttl` and the `no-transform` check (`src/proxy.c:1219`) read `Cache-Control` and
`Vary` with it.

### Fix to make

A helper that joins every line of a name with `, `, used for `Cache-Control` and `Vary` wherever
they decide anything. A test with `private` on the second line, and `Vary: Cookie` on the second
line.

## 3. Two sites on one host name share entries

### What happened

Two sites, `http://127.0.0.1:4882` to an origin answering `site A`, and `http://127.0.0.1:4883` to
one answering `site B`:

```
site on 4882: X-Cache: MISS   site A
site on 4883: X-Cache: HIT    site A
```

### Cause

`cache_build_key` (`src/proxy.c:2868`) builds the key from the method, the scheme, `host_only()`
and the URI, and `host_only` takes the port off. The cache is one per worker and shared by all
sites, so nothing else keeps them apart.

### Fix to make

Put the port in the key, or better the site's identity, since that is what decides the upstream.
A test with two sites on two ports, as above.

## 4. `ttl` keeps answers that say nothing, and some that say "already expired"

### What happened

With `cache { ttl 5m }`, the guide's example:

| Answer | With `ttl 5m` | With no `ttl` |
|---|---|---|
| A page with no cache headers, made from `Cookie: ana`, then asked for with `Cookie: bob` | **Bob gets Ana's page**, HIT | Bob gets his own |
| `Expires: 0` | **kept**, HIT | not tried |
| `Cache-Control: max-age=-1` | **kept**, HIT | not tried |
| `Cache-Control: s-maxage=0, max-age=60` | not kept, correct | not tried |

In front of Quillo, the same `ttl` gave a French page to an English visitor, and one visitor's
`User-Agent` to the next, as those pages sent no `Cache-Control`. Quillo should say more (its
Q-878), but a page saying nothing is common, and few sites expect a proxy to keep one.

The guide's example is `static.example.com`, where this is fine. Nothing warns against it on a
site with pages.

### Cause

`if (ttl < 0) ttl = c->cache_cfg->ttl;` in `cache_consider_response` (`src/proxy.c:3216`). `-1`
means "no freshness given", but `max-age=-1` parses to `-1`, and an `Expires` that does not parse
leaves it at `-1`. RFC 9111 says an invalid `Expires`, "0" especially, means already expired
(section 5.3).

### Fix to make

1. Keep "said nothing" apart from "said something invalid", which is stale and not kept.
2. Do not apply `ttl` when the request carried a `Cookie` or `Authorization`. Varnish's built-in
   rules pass such requests for the same reason.
3. Decide whether `ttl` applies to `text/html` and `application/json` at all. The safer default is
   no, with an option to allow it.
4. Say in the guide that `ttl` is for sites of static files.

## 5. `no-cache` is asked about once, then reused for 60 seconds or `ttl`

### What happened

An answer with `Cache-Control: no-cache` and an `ETag`, 20 requests over 4 seconds: the origin was
asked **2 times**, and 18 or 19 were HITs. It made no difference whether the site had `ttl`, or
whether the `304` repeated `Cache-Control`. In front of Quillo, after a file changed, three
requests in a row got the old file: `X-Cache: HIT`, `Age: 2`.

`no-cache` means a kept copy must be checked every time (RFC 9111, section 5.2.2.4). The store
path agrees: `ttl = 0; /* store, but always revalidate */` (`src/proxy.c:3215`).

### Cause

The `304` path (`src/proxy.c:2258-2262`):

```c
double nttl = response_declared_ttl(&uc->resp);
if (nttl < 0)
    nttl = c->cache_cfg->ttl;
if (nttl <= 0)
    nttl = 60; /* a validated entry stays usable for a short while */
```

`no-cache` gives `0`, which becomes 60 seconds. A `304` with no `Cache-Control` gives `-1`, which
becomes `ttl`, so 5 minutes with the guide's example. (How long was read from this code. The test
ran for 4 seconds.) `cache_entry_refresh` (`src/cache.c:195`) sets only the times, so what the
stored answer said is gone.

`/nocache` and `/plain` are in `tests/cacheback.py`, and no test calls them.

### Fix to make

Remember on the entry what the stored answer said. A `304` with its own `Cache-Control` updates
that, and one without keeps it (RFC 9111, section 4.3.4). An entry that always revalidates stays at
`0`, and the line with `60` goes. A test using `/nocache`: every request reaches the origin, and a
changed answer shows at once.

## 6. `stale` serves what `must-revalidate` forbids

### What happened

With `cache { stale 30s }`, and `Cache-Control: max-age=1, must-revalidate`: a second request
1.4 seconds later got the old answer with `X-Cache: STALE`. A `no-cache` entry was also served
stale once in 20.

### Cause

`c->cap_swr = c->cache_cfg->swr;` for every answer (`src/proxy.c:3229`). Nothing reads
`must-revalidate` or `proxy-revalidate`.

### Fix to make

`swr` is `0` when the answer says `no-cache`, `must-revalidate`, `proxy-revalidate`, or `s-maxage`
(which implies `proxy-revalidate`, RFC 9111, section 5.2.2.10). A test for each.

## 7. Different `Accept-Encoding` strings push each other out

### What happened

An origin saying `Vary: Accept-Encoding`, 60 requests:

| `Accept-Encoding` | Reached the origin | Hits |
|---|---|---|
| One string | 1 | 59 |
| `gzip, deflate, br, zstd`, `gzip, deflate, br`, `gzip, deflate`, in turn | **60** | **0** |

Browsers do not all send the same string. So a site with mixed visitors can look healthy while the
cache does nothing, and in the worst case adds work: every request stores a new entry.

### Cause

`cache_vary_values` compares the header's exact text, and one variant is kept per URL (the guide
says so). The two together mean each new string replaces the last.

### Fix to make

Problem 1's second step takes `Accept-Encoding` out of the comparison, which fixes this for
compression. For other headers, keeping a few variants per URL would help too.

## 8. Nothing can remove an entry

### What happened

An entry kept before `limer reload` was still a HIT after it. The admin API (`/upstreams`,
`/metrics`, `/config`, `/reload`, `/overrides`, `/drain`, `/undrain`, `/scale_up`, `/register`,
`/deregister`, `/broadcast`, `/registry`) has nothing for the cache. So a wrong entry, including
one from problems 1 to 4, stays until it expires, is pushed out, or Limer restarts. With
`max-age=31536000` that means a restart.

### Fix to make

`POST /cache/purge` on the admin API, by host and path or prefix. The cache is per worker, so it
has to reach each worker. A `Cache-Tag`-style tag would let Quillo purge by database table later
(FEEDBACK59's Part E), and the pool's `broadcast` could carry it between servers.

## 9. The guide's one-line `{ cache_capacity 256m }` is refused

`USERGUIDE.md:768` has the example, and `limer validate` answers `line 1: '{' must end its line`
(`src/config.c:230`). Either allow a block on one line, or write it on three lines in the guide.

## What behaved well

- `private` on the only `Cache-Control` line: a signed-in Quillo page was never given to another
  visitor.
- `Vary: Cookie` on one line: each visitor got their own page.
- `s-maxage=0` beat `max-age=60`.
- A stale entry with a validator is asked about with `If-None-Match`, and a `304` keeps the body.
- `X-Cache` and `Age` made every problem here quick to see.
- The `no-store`, `private` and `Set-Cookie` cases in `tests/run_features.sh` are the right ones
  to have. The gaps above are mostly cases next to them.

## Proposed order

| Step | Problems | Note |
|---|---|---|
| 1 | 1, first step | one condition, and stops the garbage |
| 2 | 2, 3 | answers going to the wrong visitor or site |
| 3 | 5, 6 | a stored flag, and `swr` per answer |
| 4 | 4 | a decision on what `ttl` covers |
| 5 | 1, second step, and 7 | one plain copy, compressed per client |
| 6 | 8, 9 | |

Each step adds its cases to `tests/cacheback.py` and `tests/run_features.sh`, and the guide's
Response caching section follows.

## To reproduce

`back.py`, the test origin. Each body counts the origin's hits, so a kept copy shows:

```python
#!/usr/bin/env python3
import gzip, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
LOCK = threading.Lock(); HITS = {}
BIG = b"<html><body>" + b"quillo " * 600 + b"</body></html>"
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def out(self, code, body, hdrs):
        self.send_response(code)
        for k, v in hdrs: self.send_header(k, v)
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)
    def do_GET(self):
        p = self.path.split("?")[0]
        with LOCK:
            HITS[p] = HITS.get(p, 0) + 1; n = HITS[p]
        inm = self.headers.get("If-None-Match"); ck = self.headers.get("Cookie", "none")
        text = ("Content-Type", "text/plain")
        if p == "/nc":
            cc = ("Cache-Control", "no-cache"); et = ("ETag", '"n1"')
            if inm == '"n1"': return self.out(304, b"", [et, cc])
            return self.out(200, b"v%d" % n, [et, cc, text])
        if p == "/mr":
            return self.out(200, b"v%d" % n, [("Cache-Control", "max-age=1, must-revalidate"), text])
        if p == "/two-cc":
            return self.out(200, ("for %s" % ck).encode(), [("Cache-Control", "max-age=60"), ("Cache-Control", "private"), text])
        if p == "/two-vary":
            return self.out(200, ("for %s" % ck).encode(), [("Cache-Control", "public, max-age=60"), ("Vary", "Accept-Encoding"), ("Vary", "Cookie"), text])
        if p == "/exp0":
            return self.out(200, b"v%d" % n, [("Expires", "0"), text])
        if p == "/neg":
            return self.out(200, b"v%d" % n, [("Cache-Control", "max-age=-1"), text])
        if p == "/page":
            return self.out(200, ("<p>for %s</p>" % ck).encode(), [("Content-Type", "text/html")])
        if p == "/gz":
            h = [("Cache-Control", "max-age=60"), ("Vary", "Accept-Encoding"), ("Content-Type", "text/html")]
            if "gzip" in self.headers.get("Accept-Encoding", ""):
                return self.out(200, gzip.compress(BIG), h + [("Content-Encoding", "gzip")])
            return self.out(200, BIG, h)
        self.out(404, b"no", [])
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
```

`limer.conf`, run with `python3 back.py 4860` and `limer run -c limer.conf -w 1 -p limer.pid`:

```
{
    admin off
    log_level warn
}
http://127.0.0.1:4861 {
    cache {
        ttl 5m
    }
    reverse_proxy 127.0.0.1:4860
}
http://127.0.0.1:4863 {
    cache {
        stale 30s
    }
    reverse_proxy 127.0.0.1:4860
}
```

The requests. Problem 3 needs two origins that answer differently, on two sites of the same host.

```sh
L=http://127.0.0.1:4861
# 1: the second answer has no Content-Encoding, and its body starts 1f 8b
curl -s -o /dev/null -H 'Accept-Encoding: gzip' $L/gz
curl -s -D - -o out -H 'Accept-Encoding: gzip' $L/gz | grep -i -E 'x-cache|content-encoding'
head -c 2 out | xxd
# 2: both say "for ana"
curl -s -H 'Cookie: ana' $L/two-cc; echo; curl -s -H 'Cookie: bob' $L/two-cc; echo
curl -s -H 'Cookie: ana' $L/two-vary; echo; curl -s -H 'Cookie: bob' $L/two-vary; echo
# 4: both say "for ana", then v1 twice each
curl -s -H 'Cookie: ana' $L/page; echo; curl -s -H 'Cookie: bob' $L/page; echo
curl -s $L/exp0; echo; curl -s $L/exp0; echo
curl -s $L/neg; echo; curl -s $L/neg; echo
# 5: MISS, then HIT each time: only the second request asks the origin
for i in 1 2 3 4; do curl -s -D - -o /dev/null $L/nc | grep -i x-cache; done
# 6: v1, then v1 again with X-Cache: STALE
curl -s http://127.0.0.1:4863/mr; echo; sleep 1.4
curl -s -D - http://127.0.0.1:4863/mr | grep -a -i -E 'x-cache|^v'
# 7: MISS every time
for i in 1 2 3 4 5 6; do
  for e in 'gzip, deflate, br, zstd' 'gzip, deflate, br' 'gzip, deflate'; do
    curl -s -D - -o /dev/null -H "Accept-Encoding: $e" "$L/gz?7" | grep -i x-cache
  done
done
```
