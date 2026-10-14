/*
 * fuzz.c - mutation fuzzer for Limer's parsers.
 *
 * Built with AddressSanitizer and UBSan by `make fuzz` (see Makefile), it
 * mutates seed inputs and feeds them to the HTTP head parsers, the chunked
 * decoder, the JSON extractor, the form/cookie key extractors and the config
 * parser, checking the invariants each one promises. A crash, a sanitizer
 * report or a violated invariant fails the run.
 *
 *   ./build/fuzz [iterations] [seed]
 */
#include "../src/limer.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t rng_state;
static uint64_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static const char *req_seeds[] = {
    "POST /api/orders?x=1 HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 27\r\nX-Tenant: acme\r\n"
    "Cookie: sid=abc; a=1\r\nConnection: keep-alive\r\n\r\n{\"type\":\"order\",\"id\":42}",
    "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    "GET http://example.com/p?q=1 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nhello",
    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
};
static const char *chunk_seeds[] = {
    "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-T: 1\r\n\r\n",
    "A\nabcdefghij\n0\n\n",
    "FFFFFFFF\r\n",
    "0\r\n\r\n",
};
static const char *json_seeds[] = {
    "{\"type\":\"order\",\"n\":-1.5e3,\"ok\":true,\"nil\":null,\"user\":{\"id\":\"u1\",\"tags\":[\"a\",{\"k\":\"v\"},3]},"
    "\"esc\":\"q\\\"\\\\\\/\\n\\u00e9\\ud83d\\ude00\",\"e\":{},\"a\":[]}",
    "[1,[2,[3,[4,{\"x\":[5]}]]]]",
    "{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":1}}}}}",
};
static const char *json_paths[] = { "type", "user.id", "user.tags[1].k", "user.tags[2]", "a.a.a.a.a", "[1][1][1][1].x[0]", "", "esc", "nope", "a[0]", "e.x" };
static const char *cfg_seeds[] = {
    "{\n workers 2\n admin 127.0.0.1:2019\n log_level debug\n}\n"
    ":8080, 127.0.0.1:8081 {\n max_body 1m\n read_timeout 5s\n log\n"
    " route orders {\n  match method POST\n  match json type == order refund\n  match json amount > 10\n"
    "  match header X-T ~ \"^a.c$\"\n  match remote_ip 10.0.0.0/8\n  to 127.0.0.1:9001 weight=3 127.0.0.1:9002\n"
    "  lb_policy hash json customer.id\n  header_up X-A \"a b\"\n  header_down -Server\n }\n"
    " route {\n  match path /ping\n  respond 204 \"x\"\n }\n"
    " reverse_proxy 127.0.0.1:9003 {\n  lb_policy least_conn\n  health_uri /h\n  keepalive off\n }\n}\n",
};

/* mutate `in` into `out` (NUL-terminated); returns new length */
static size_t mutate(const char *in, size_t inlen, char *out, size_t cap)
{
    size_t n = inlen < cap - 1 ? inlen : cap - 1;
    memcpy(out, in, n);
    int rounds = 1 + (int)(rnd() % 4);
    static const char *tokens[] = {
        "\r\n", "\n", "\r", ":", " ", "\t", "chunked", "Content-Length: ", "Transfer-Encoding: ", "0\r\n\r\n",
        "\"", "\\u", "\\", "{", "}", "[", "]", ",", "%", "&", "=", ";", "9999999999999999999", "-", ".", "e",
        "match ", "to ", "lb_policy ", "}\n", "{\n", "\x00", "\xff", "HTTP/1.1", "GET ", "Connection: ",
    };
    for (int r = 0; r < rounds; r++) {
        unsigned op = (unsigned)(rnd() % 6);
        size_t pos = n ? (size_t)(rnd() % (n + 1)) : 0;
        if (op == 0 && n > 0) {               /* flip a byte */
            out[rnd() % n] = (char)(rnd() & 0xff);
        } else if (op == 1 && n > 0) {        /* delete a range */
            size_t len = 1 + (size_t)(rnd() % 8);
            if (pos + len > n)
                len = n - pos;
            memmove(out + pos, out + pos + len, n - pos - len);
            n -= len;
        } else if (op == 2) {                 /* insert a token */
            const char *t = tokens[rnd() % (sizeof tokens / sizeof tokens[0])];
            size_t tl = strlen(t) ? strlen(t) : 1;
            if (n + tl < cap - 1) {
                memmove(out + pos + tl, out + pos, n - pos);
                memcpy(out + pos, t, tl);
                n += tl;
            }
        } else if (op == 3 && n > 0) {        /* duplicate a range */
            size_t len = 1 + (size_t)(rnd() % 32);
            if (pos + len > n)
                len = n - pos;
            if (n + len < cap - 1) {
                memmove(out + pos + len, out + pos, n - pos);
                memcpy(out + pos, out + pos + len, len);
                n += len;
            }
        } else if (op == 4) {                 /* truncate */
            n = pos;
        } else if (n > 0) {                   /* set a byte to a boundary value */
            static const char vals[] = { 0, 1, ' ', '\r', '\n', 0x7f, (char)0x80, (char)0xff, '{', '}', '"', '\\' };
            out[rnd() % n] = vals[rnd() % sizeof vals];
        }
    }
    out[n] = 0;
    return n;
}

static void die(const char *what, const char *in, size_t n)
{
    fprintf(stderr, "fuzz: invariant violated: %s\ninput (%zu bytes): ", what, n);
    for (size_t i = 0; i < n && i < 300; i++)
        fputc((in[i] >= 32 && in[i] < 127) ? in[i] : '.', stderr);
    fputc('\n', stderr);
    exit(1);
}

static void fuzz_http(const char *in, size_t n)
{
    http_req_t r;
    http_req_init(&r);
    size_t consumed = 12345;
    int rc = http_parse_request_head(&r, in, n, &consumed);
    if (rc == 1) {
        if (consumed > n)
            die("request consumed > len", in, n);
        if (!r.method || !r.uri || !r.path || !r.query)
            die("request fields missing", in, n);
        if (r.chunked && r.content_length >= 0)
            die("CL and TE both accepted", in, n);
        if (r.nhdr > HTTP_MAX_HEADERS)
            die("too many headers accepted", in, n);
        for (int i = 0; i < r.nhdr; i++)
            if (strchr(r.hdrs[i].name, ' ') || strchr(r.hdrs[i].name, ':') || !*r.hdrs[i].name)
                die("bad header name accepted", in, n);
        /* exercise helpers on the parsed request */
        buf_t out;
        buf_init(&out);
        keysrc_t keys[] = { { KS_HEADER, (char *)"Cookie" }, { KS_COOKIE, (char *)"sid" }, { KS_QUERY, (char *)"x" },
                            { KS_HOST, NULL }, { KS_PATH, NULL }, { KS_URI, NULL }, { KS_METHOD, NULL } };
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        req_ctx_t ctx = { &r, (struct sockaddr *)&sa, sizeof sa, "1.2.3.4", 0, NULL };
        for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++)
            key_extract(&keys[k], &ctx, &out);
        buf_free(&out);
    } else if (rc != 0 && rc != -1 && rc != -2) {
        die("unexpected request rc", in, n);
    }
    http_req_free(&r);

    http_resp_t s;
    http_resp_init(&s);
    rc = http_parse_response_head(&s, in, n, &consumed);
    if (rc == 1) {
        if (consumed > n || s.status < 100 || s.status > 999)
            die("bad response parse", in, n);
        if (s.chunked && s.content_length >= 0)
            die("response CL and TE both accepted", in, n);
    }
    http_resp_free(&s);
}

static void fuzz_chunk(const char *in, size_t n)
{
    /* whole-buffer and byte-at-a-time scans must agree */
    chunk_state_t a, b;
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    buf_t oa, ob;
    buf_init(&oa);
    buf_init(&ob);
    size_t ca = 0;
    int ra = http_chunk_scan(&a, in, n, &ca, &oa);
    if (ca > n)
        die("chunk consumed > len", in, n);
    size_t cb = 0;
    int rb = 0;
    while (cb < n) {
        size_t c = 0;
        rb = http_chunk_scan(&b, in + cb, 1, &c, &ob);
        if (rb < 0)
            break;
        if (c == 0)
            break; /* done */
        cb += c;
    }
    if ((ra < 0) != (rb < 0))
        die("chunk scan result differs between whole and bytewise", in, n);
    if (ra == 0 && rb == 0) {
        if (ca != cb || a.done != b.done)
            die("chunk scan consumed/done differs", in, n);
        if (buf_readable(&oa) != buf_readable(&ob) ||
            (buf_readable(&oa) > 0 && memcmp(buf_rptr(&oa), buf_rptr(&ob), buf_readable(&oa)) != 0))
            die("chunk decoded output differs", in, n);
        if (buf_readable(&oa) > n)
            die("chunk decoded more than input", in, n);
    }
    buf_free(&oa);
    buf_free(&ob);
}

static void fuzz_json(const char *in, size_t n)
{
    buf_t out;
    buf_init(&out);
    for (size_t i = 0; i < sizeof json_paths / sizeof json_paths[0]; i++) {
        int t = json_extract(in, n, json_paths[i], &out);
        if (t == JSON_STRING || t == JSON_OBJECT || t == JSON_ARRAY || t == JSON_NUMBER) {
            if (buf_readable(&out) > n + 4 * n) /* decoded strings can only shrink; raw slices are bounded */
                die("json output larger than input", in, n);
        }
    }
    /* form/body extraction on the same bytes */
    http_req_t r;
    http_req_init(&r);
    buf_append(&r.body, in, n);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    req_ctx_t ctx = { &r, (struct sockaddr *)&sa, sizeof sa, "1.2.3.4", 0, NULL };
    keysrc_t k = { KS_FORM, (char *)"a" };
    key_extract(&k, &ctx, &out);
    k.src = KS_JSON; k.name = (char *)"user.id";
    key_extract(&k, &ctx, &out);
    http_req_free(&r);
    buf_free(&out);
}

static void fuzz_config(const char *in, size_t n)
{
    (void)n;
    char err[512];
    config_t *c = config_parse(in, "fuzz", err, sizeof err);
    if (c) {
        if (c->nservers <= 0)
            die("config accepted with no servers", in, n);
        for (int i = 0; i < c->nservers; i++) {
            server_t *s = c->servers[i];
            if (!s->is_admin && s->nroutes <= 0)
                die("server accepted without routes", in, n);
            for (int r = 0; r < s->nroutes; r++) {
                route_t *rt = s->routes[r];
                if (rt->kind == ROUTE_PROXY && (!rt->pool || rt->pool->nups <= 0 || rt->pool->total_weight <= 0))
                    die("proxy route without usable pool", in, n);
            }
        }
        config_ref(c);
        config_unref(c);
        config_unref(c);
    } else if (!err[0]) {
        die("config rejected without an error message", in, n);
    }
}

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    rng_state = argc > 2 ? strtoull(argv[2], NULL, 10) : (uint64_t)time(NULL) * 2654435761u;
    if (!rng_state)
        rng_state = 1;
    uint64_t seed = rng_state;
    config_no_dns = 1;   /* mutated host names must not wait on DNS (seconds each on macOS) */
    log_level = LOG_ERROR;
    static char buf[1 << 16];
    for (long i = 0; i < iters; i++) {
        unsigned which = (unsigned)(rnd() % 4);
        size_t n;
        switch (which) {
        case 0: {
            const char *s = req_seeds[rnd() % (sizeof req_seeds / sizeof req_seeds[0])];
            n = mutate(s, strlen(s), buf, sizeof buf);
            fuzz_http(buf, n);
            fuzz_chunk(buf, n);
            break;
        }
        case 1: {
            const char *s = chunk_seeds[rnd() % (sizeof chunk_seeds / sizeof chunk_seeds[0])];
            n = mutate(s, strlen(s), buf, sizeof buf);
            fuzz_chunk(buf, n);
            break;
        }
        case 2: {
            const char *s = json_seeds[rnd() % (sizeof json_seeds / sizeof json_seeds[0])];
            n = mutate(s, strlen(s), buf, sizeof buf);
            fuzz_json(buf, n);
            break;
        }
        default: {
            const char *s = cfg_seeds[rnd() % (sizeof cfg_seeds / sizeof cfg_seeds[0])];
            n = mutate(s, strlen(s), buf, sizeof buf);
            /* embedded NULs terminate the config text; that is fine */
            fuzz_config(buf, n);
            break;
        }
        }
    }
    printf("fuzz: %ld iterations ok (seed %llu)\n", iters, (unsigned long long)seed);
    return 0;
}
