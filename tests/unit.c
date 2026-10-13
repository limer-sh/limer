/*
 * unit.c - unit tests for Limer's parsers, matchers and balancing policies.
 * Built by `make unit`, run by `make check`.
 */
#include "../src/limer.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int checks, failures;
static const char *current;

#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    fprintf(stderr, "  FAIL %s:%d [%s] %s\n", __FILE__, __LINE__, current, #cond); } } while (0)
#define CHECK_STR(a, b) do { checks++; const char *_a = (a), *_b = (b); \
    if (!_a || !_b || strcmp(_a, _b) != 0) { failures++; \
    fprintf(stderr, "  FAIL %s:%d [%s] %s == \"%s\" (got \"%s\")\n", __FILE__, __LINE__, current, #a, _b, _a ? _a : "(null)"); } } while (0)
#define TEST(name) static void name(void); static void name##_run(void) { current = #name; name(); } static void name(void)

/* ------------------------------------------------------------------ */
TEST(test_buf)
{
    buf_t b;
    buf_init(&b);
    CHECK(buf_readable(&b) == 0);
    buf_puts(&b, "hello ");
    buf_printf(&b, "%d-%s", 42, "x");
    CHECK(buf_readable(&b) == 10);
    CHECK(memcmp(buf_rptr(&b), "hello 42-x", 10) == 0);
    buf_consume(&b, 6);
    CHECK(buf_readable(&b) == 4);
    CHECK(memcmp(buf_rptr(&b), "42-x", 4) == 0);
    buf_compact(&b);
    CHECK(b.off == 0 && b.len == 4);
    buf_consume(&b, 4);
    CHECK(b.len == 0 && b.off == 0);
    char big[70000];
    memset(big, 'z', sizeof big);
    buf_append(&b, big, sizeof big);
    CHECK(buf_readable(&b) == sizeof big);
    buf_consume(&b, 100000); /* over-consume is clamped */
    CHECK(buf_readable(&b) == 0);
    buf_free(&b);
}

/* ------------------------------------------------------------------ */
TEST(test_util)
{
    double d;
    size_t sz;
    CHECK(parse_duration("30s", &d) == 0 && d == 30);
    CHECK(parse_duration("500ms", &d) == 0 && d == 0.5);
    CHECK(parse_duration("2m", &d) == 0 && d == 120);
    CHECK(parse_duration("1h", &d) == 0 && d == 3600);
    CHECK(parse_duration("1.5s", &d) == 0 && d == 1.5);
    CHECK(parse_duration("7", &d) == 0 && d == 7);
    CHECK(parse_duration("-1s", &d) < 0);
    CHECK(parse_duration("abc", &d) < 0);
    CHECK(parse_duration("5x", &d) < 0);
    CHECK(parse_size("8m", &sz) == 0 && sz == 8u * 1024 * 1024);
    CHECK(parse_size("512k", &sz) == 0 && sz == 512u * 1024);
    CHECK(parse_size("1g", &sz) == 0 && sz == 1024u * 1024 * 1024);
    CHECK(parse_size("100", &sz) == 0 && sz == 100);
    CHECK(parse_size("4MiB", &sz) == 0 && sz == 4u * 1024 * 1024);
    CHECK(parse_size("4mb", &sz) == 0);
    CHECK(parse_size("x", &sz) < 0);
    CHECK(parse_size("4q", &sz) < 0);

    char *h;
    int port;
    CHECK(parse_hostport("127.0.0.1:8080", &h, &port, 0) == 0 && port == 8080);
    CHECK_STR(h, "127.0.0.1"); free(h);
    CHECK(parse_hostport(":9000", &h, &port, 0) == 0 && port == 9000);
    CHECK_STR(h, ""); free(h);
    CHECK(parse_hostport("[::1]:443", &h, &port, 0) == 0 && port == 443);
    CHECK_STR(h, "::1"); free(h);
    CHECK(parse_hostport("http://example.com:81/", &h, &port, 0) == 0 && port == 81);
    CHECK_STR(h, "example.com"); free(h);
    CHECK(parse_hostport("example.com", &h, &port, 80) == 0 && port == 80);
    free(h);
    CHECK(parse_hostport("host:99999", &h, &port, 0) < 0);
    CHECK(parse_hostport("host:abc", &h, &port, 0) < 0);
    CHECK(parse_hostport("[::1", &h, &port, 0) < 0);
    CHECK(parse_hostport("host", &h, &port, 0) < 0); /* no default port */

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, "10.1.2.3", &sa.sin_addr);
    CHECK(cidr_match("10.0.0.0/8", (struct sockaddr *)&sa));
    CHECK(cidr_match("10.1.2.3", (struct sockaddr *)&sa));
    CHECK(cidr_match("10.1.2.0/24", (struct sockaddr *)&sa));
    CHECK(!cidr_match("10.1.3.0/24", (struct sockaddr *)&sa));
    CHECK(!cidr_match("192.168.0.0/16", (struct sockaddr *)&sa));
    CHECK(!cidr_match("fd00::/8", (struct sockaddr *)&sa));
    CHECK(!cidr_match("garbage", (struct sockaddr *)&sa));
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof sa6);
    sa6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::ffff:10.1.2.3", &sa6.sin6_addr);
    CHECK(cidr_match("10.0.0.0/8", (struct sockaddr *)&sa6)); /* v4-mapped */
    inet_pton(AF_INET6, "fd00::1", &sa6.sin6_addr);
    CHECK(cidr_match("fd00::/8", (struct sockaddr *)&sa6));
    CHECK(!cidr_match("fe80::/10", (struct sockaddr *)&sa6));
    char ip[80];
    sockaddr_to_str((struct sockaddr *)&sa6, ip, sizeof ip, 1);
    CHECK_STR(ip, "[fd00::1]:0");

    char out[64];
    CHECK(url_decode("a%20b+c%2F", 10, out, sizeof out) == 6);
    CHECK_STR(out, "a b c/");
    CHECK(url_decode("%zz%4", 5, out, sizeof out) == 5);
    CHECK_STR(out, "%zz%4");
    CHECK(url_decode("abcdef", 6, out, 4) < 0);

    CHECK(glob_match("/api/*", "/api/v1/x"));
    CHECK(glob_match("/api/*", "/api/"));
    CHECK(!glob_match("/api/*", "/apix"));
    CHECK(glob_match("*.example.com", "a.b.example.com"));
    CHECK(glob_match("/a?c", "/abc"));
    CHECK(!glob_match("/a?c", "/abbc"));
    CHECK(glob_match("*", ""));
    CHECK(glob_match("/x", "/x") && !glob_match("/x", "/y"));

    CHECK(is_numeric("12.5", &d) && d == 12.5);
    CHECK(is_numeric("-3", &d) && d == -3);
    CHECK(!is_numeric("12a", &d));
    CHECK(!is_numeric("", &d));
    CHECK(!is_numeric("nan", &d));

    CHECK(hash64("abc", 3) == hash64("abc", 3));
    CHECK(hash64("abc", 3) != hash64("abd", 3));
    CHECK(hash64_seed("abc", 3, 1) != hash64_seed("abc", 3, 2));
    CHECK(strcaseeq("Content-Length", "content-length"));
    CHECK(!strcaseeq(NULL, "x"));
}

/* ------------------------------------------------------------------ */
static int parse_req(http_req_t *r, const char *text, size_t *consumed)
{
    http_req_free(r);
    http_req_init(r);
    return http_parse_request_head(r, text, strlen(text), consumed);
}

TEST(test_http_request)
{
    http_req_t r;
    http_req_init(&r);
    size_t n;

    CHECK(parse_req(&r, "GET /a/b?x=1&y=2 HTTP/1.1\r\nHost: h\r\nX-A: 1\r\n\r\nrest", &n) == 1);
    CHECK(n == strlen("GET /a/b?x=1&y=2 HTTP/1.1\r\nHost: h\r\nX-A: 1\r\n\r\n"));
    CHECK_STR(r.method, "GET");
    CHECK_STR(r.path, "/a/b");
    CHECK_STR(r.query, "x=1&y=2");
    CHECK_STR(r.uri, "/a/b?x=1&y=2");
    CHECK(r.minor == 1 && r.keep_alive && !r.chunked && r.content_length == -1);
    CHECK_STR(http_hdr_get(r.hdrs, r.nhdr, "x-a"), "1");
    CHECK(http_hdr_get(r.hdrs, r.nhdr, "nope") == NULL);

    /* LF-only line endings and leading CRLF are tolerated */
    CHECK(parse_req(&r, "\r\n\r\nPOST / HTTP/1.1\nHost: h\nContent-Length: 3\n\nabc", &n) == 1);
    CHECK(r.content_length == 3);
    CHECK(n == 4 + strlen("POST / HTTP/1.1\nHost: h\nContent-Length: 3\n\n"));

    /* HTTP/1.0 defaults to close unless keep-alive requested */
    CHECK(parse_req(&r, "GET / HTTP/1.0\r\n\r\n", &n) == 1 && !r.keep_alive);
    CHECK(parse_req(&r, "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", &n) == 1 && r.keep_alive);
    CHECK(parse_req(&r, "GET / HTTP/1.1\r\nConnection: close\r\n\r\n", &n) == 1 && !r.keep_alive);
    CHECK(parse_req(&r, "GET / HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n", &n) == 1 && r.upgrade);
    CHECK(parse_req(&r, "GET / HTTP/1.1\r\nConnection: Upgrade\r\n\r\n", &n) == 1 && !r.upgrade);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n", &n) == 1 && r.expect_100);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &n) == 1 && r.chunked);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nTransfer-Encoding: Chunked\r\n\r\n", &n) == 1 && r.chunked);

    /* absolute-form target */
    CHECK(parse_req(&r, "GET http://example.com/p?q HTTP/1.1\r\nHost: example.com\r\n\r\n", &n) == 1);
    CHECK_STR(r.path, "/p");
    CHECK_STR(r.query, "q");
    CHECK(parse_req(&r, "GET http://example.com HTTP/1.1\r\n\r\n", &n) == 1);
    CHECK_STR(r.path, "/");

    /* header value trimming, case-insensitive lookup */
    CHECK(parse_req(&r, "GET / HTTP/1.1\r\nX-T:   spaced value \t\r\n\r\n", &n) == 1);
    CHECK_STR(http_hdr_get(r.hdrs, r.nhdr, "X-T"), "spaced value");

    /* incomplete */
    CHECK(parse_req(&r, "GET / HTTP/1.1\r\nHost: h\r\n", &n) == 0);
    CHECK(parse_req(&r, "", &n) == 0);

    /* smuggling guards and malformed input */
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", &n) == 1);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nContent-Length: 1x\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "POST / HTTP/1.1\r\nTransfer-Encoding: xchunked\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "GET / HTTP/1.1\r\nHost : h\r\n\r\n", &n) == -1);           /* space before colon */
    CHECK(parse_req(&r, "GET / HTTP/1.1\r\nHost: h\r\n continued\r\n\r\n", &n) == -1); /* obs-fold */
    CHECK(parse_req(&r, "GET / HTTP/1.1\r\n: novalue\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "GET / HTTP/1.1\r\nno-colon\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "GET / HTTP/1.1\r\nBad\x01Name: x\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "GET / HTTP/2.0\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "GET / HTTP/1.1x\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "GET /\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "G\x7f""ET / HTTP/1.1\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "GET /a\x01""b HTTP/1.1\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "GET  / HTTP/1.1\r\n\r\n", &n) == -1);
    CHECK(parse_req(&r, "GARBAGE\r\n\r\n", &n) == -1);
    /* embedded NUL bytes (found by fuzzing: used to crash the parser) */
    {
        const char nul_req[] = "GET /a\0b HTTP/1.1\r\nHost: h\r\n\r\n";
        http_req_free(&r);
        http_req_init(&r);
        CHECK(http_parse_request_head(&r, nul_req, sizeof nul_req - 1, &n) == -1);
        const char nul_hdr[] = "GET / HTTP/1.1\r\nX: a\0b\r\n\r\n";
        http_req_free(&r);
        http_req_init(&r);
        CHECK(http_parse_request_head(&r, nul_hdr, sizeof nul_hdr - 1, &n) == -1);
        http_resp_t rs;
        http_resp_init(&rs);
        const char nul_resp[] = "HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n";
        CHECK(http_parse_response_head(&rs, nul_resp, sizeof nul_resp - 1, &n) == -1);
        http_resp_free(&rs);
    }

    /* too many headers */
    buf_t big;
    buf_init(&big);
    buf_puts(&big, "GET / HTTP/1.1\r\n");
    for (int i = 0; i < HTTP_MAX_HEADERS + 1; i++)
        buf_printf(&big, "X-%d: v\r\n", i);
    buf_puts(&big, "\r\n");
    buf_append(&big, "", 1);
    CHECK(parse_req(&r, buf_rptr(&big), &n) == -1);
    /* too large */
    buf_reset(&big);
    buf_puts(&big, "GET / HTTP/1.1\r\nX: ");
    for (int i = 0; i < HTTP_MAX_HEAD + 10; i++)
        buf_append(&big, "a", 1);
    buf_append(&big, "", 1);
    CHECK(parse_req(&r, buf_rptr(&big), &n) == -2);
    buf_free(&big);
    http_req_free(&r);

    CHECK(http_hdr_is_hop_by_hop("Connection") && http_hdr_is_hop_by_hop("transfer-encoding") && http_hdr_is_hop_by_hop("TE"));
    CHECK(!http_hdr_is_hop_by_hop("Content-Type"));
    CHECK(http_hdr_connection_has("keep-alive, X-Secret", "x-secret"));
    CHECK(!http_hdr_connection_has("keep-alive", "keep"));
    CHECK(!http_hdr_connection_has(NULL, "close"));
    CHECK_STR(http_status_reason(502), "Bad Gateway");
}

TEST(test_http_response)
{
    http_resp_t r;
    http_resp_init(&r);
    size_t n;
    const char *ok = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX: y\r\n\r\nhello";
    CHECK(http_parse_response_head(&r, ok, strlen(ok), &n) == 1);
    CHECK(r.status == 200 && r.content_length == 5 && r.keep_alive && !r.chunked);
    CHECK_STR(r.reason, "OK");
    CHECK(n == strlen(ok) - 5);
    http_resp_free(&r);
    const char *nr = "HTTP/1.0 404\r\n\r\n";
    CHECK(http_parse_response_head(&r, nr, strlen(nr), &n) == 1 && r.status == 404 && !r.keep_alive);
    CHECK_STR(r.reason, "");
    http_resp_free(&r);
    const char *ch = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    CHECK(http_parse_response_head(&r, ch, strlen(ch), &n) == 1 && r.chunked && !r.keep_alive);
    http_resp_free(&r);
    const char *bad1 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
    CHECK(http_parse_response_head(&r, bad1, strlen(bad1), &n) == -1);
    http_resp_free(&r);
    const char *bad2 = "HTTP/1.1 20 OK\r\n\r\n";
    CHECK(http_parse_response_head(&r, bad2, strlen(bad2), &n) == -1);
    http_resp_free(&r);
    const char *bad3 = "HTTP/1.1 200OK\r\n\r\n";
    CHECK(http_parse_response_head(&r, bad3, strlen(bad3), &n) == -1);
    http_resp_free(&r);
    const char *bad4 = "SMTP 200 OK\r\n\r\n";
    CHECK(http_parse_response_head(&r, bad4, strlen(bad4), &n) == -1);
    http_resp_free(&r);
    CHECK(http_parse_response_head(&r, "HTTP/1.1 200 OK\r\n", 17, &n) == 0);
    http_resp_free(&r);
}

/* feed the scanner one byte at a time to exercise every state transition */
static int scan_bytewise(const char *in, size_t len, buf_t *out, size_t *consumed_total)
{
    chunk_state_t cs;
    memset(&cs, 0, sizeof cs);
    size_t i = 0;
    while (i < len && !cs.done) {
        size_t c = 0;
        if (http_chunk_scan(&cs, in + i, 1, &c, out) < 0)
            return -1;
        i += c;
        if (c == 0)
            break;
    }
    *consumed_total = i;
    return cs.done ? 1 : 0;
}

TEST(test_chunked)
{
    buf_t out;
    buf_init(&out);
    size_t n;
    chunk_state_t cs;

    const char *msg = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\nNEXT";
    memset(&cs, 0, sizeof cs);
    CHECK(http_chunk_scan(&cs, msg, strlen(msg), &n, &out) == 0 && cs.done);
    CHECK(n == strlen(msg) - 4);
    CHECK(buf_readable(&out) == 11 && memcmp(buf_rptr(&out), "hello world", 11) == 0);

    buf_reset(&out);
    CHECK(scan_bytewise(msg, strlen(msg), &out, &n) == 1 && n == strlen(msg) - 4);
    CHECK(buf_readable(&out) == 11 && memcmp(buf_rptr(&out), "hello world", 11) == 0);

    /* extensions, uppercase hex, LF-only, trailers */
    const char *ext = "A;name=\"v\"\r\n0123456789\r\nB\nabcdefghijk\n0\r\nX-Trailer: 1\r\nY: 2\r\n\r\n";
    buf_reset(&out);
    CHECK(scan_bytewise(ext, strlen(ext), &out, &n) == 1 && n == strlen(ext));
    CHECK(buf_readable(&out) == 21);
    memset(&cs, 0, sizeof cs);
    buf_reset(&out);
    CHECK(http_chunk_scan(&cs, ext, strlen(ext), &n, &out) == 0 && cs.done && n == strlen(ext));
    CHECK(buf_readable(&out) == 21);

    /* scanning without an output buffer (passthrough mode) */
    memset(&cs, 0, sizeof cs);
    CHECK(http_chunk_scan(&cs, msg, strlen(msg), &n, NULL) == 0 && cs.done && n == strlen(msg) - 4);

    /* trailer line split across reads must not be mistaken for the end */
    memset(&cs, 0, sizeof cs);
    const char *t1 = "0\r\nX-Foo: bar";
    const char *t2 = "\r\nX-Bar: baz\r\n\r\n";
    CHECK(http_chunk_scan(&cs, t1, strlen(t1), &n, NULL) == 0 && !cs.done && n == strlen(t1));
    CHECK(http_chunk_scan(&cs, t2, strlen(t2), &n, NULL) == 0 && cs.done && n == strlen(t2));

    /* incomplete input: everything consumed, not done */
    memset(&cs, 0, sizeof cs);
    CHECK(http_chunk_scan(&cs, "5\r\nhel", 6, &n, NULL) == 0 && !cs.done && n == 6);

    /* malformed */
    const char *bad[] = {
        "\r\n",             /* no size digits */
        "zz\r\n",           /* not hex */
        "5\rX",             /* CR not followed by LF */
        "5\r\nhello\r\r",   /* bad chunk terminator */
        "5\r\nhelloX",      /* no terminator */
        ";ext\r\n",         /* extension without size */
        "0\r\n\rX",         /* bad trailer terminator */
        "FFFFFFFFFFFFFFFFFFFFF\r\n", /* size overflow */
        NULL
    };
    for (int i = 0; bad[i]; i++) {
        memset(&cs, 0, sizeof cs);
        int rc = http_chunk_scan(&cs, bad[i], strlen(bad[i]), &n, NULL);
        checks++;
        if (rc != -1) {
            failures++;
            fprintf(stderr, "  FAIL [%s] malformed chunk input %d accepted\n", current, i);
        }
    }
    buf_free(&out);
}

/* ------------------------------------------------------------------ */
static int jx(const char *doc, const char *path, buf_t *out)
{
    return json_extract(doc, strlen(doc), path, out);
}

TEST(test_json)
{
    buf_t out;
    buf_init(&out);
    const char *doc = "{ \"type\" : \"order\", \"n\": -12.5e1, \"ok\": true, \"nil\": null,"
                      " \"user\": {\"id\": \"u-1\", \"tags\": [\"a\", {\"k\": \"deep\"}, 3]},"
                      " \"esc\": \"q\\\"b\\\\s\\/n\\nu\\u00e9\\ud83d\\ude00\", \"empty\": {}, \"arr\": [] }";
    CHECK(jx(doc, "type", &out) == JSON_STRING);
    CHECK(buf_readable(&out) == 5 && memcmp(buf_rptr(&out), "order", 5) == 0);
    CHECK(jx(doc, "n", &out) == JSON_NUMBER && buf_readable(&out) == 7 && memcmp(buf_rptr(&out), "-12.5e1", 7) == 0);
    CHECK(jx(doc, "ok", &out) == JSON_BOOL && memcmp(buf_rptr(&out), "true", 4) == 0);
    CHECK(jx(doc, "nil", &out) == JSON_NULL);
    CHECK(jx(doc, "user.id", &out) == JSON_STRING && memcmp(buf_rptr(&out), "u-1", 3) == 0);
    CHECK(jx(doc, "user.tags[0]", &out) == JSON_STRING && memcmp(buf_rptr(&out), "a", 1) == 0);
    CHECK(jx(doc, "user.tags[1].k", &out) == JSON_STRING && memcmp(buf_rptr(&out), "deep", 4) == 0);
    CHECK(jx(doc, "user.tags[2]", &out) == JSON_NUMBER && memcmp(buf_rptr(&out), "3", 1) == 0);
    CHECK(jx(doc, "user.tags", &out) == JSON_ARRAY && buf_rptr(&out)[0] == '[');
    CHECK(jx(doc, "user", &out) == JSON_OBJECT && buf_rptr(&out)[0] == '{' && buf_rptr(&out)[buf_readable(&out) - 1] == '}');
    CHECK(jx(doc, "esc", &out) == JSON_STRING);
    CHECK(buf_readable(&out) == strlen("q\"b\\s/n\nu\xc3\xa9\xf0\x9f\x98\x80") &&
          memcmp(buf_rptr(&out), "q\"b\\s/n\nu\xc3\xa9\xf0\x9f\x98\x80", buf_readable(&out)) == 0);
    CHECK(jx(doc, "", &out) == JSON_OBJECT);
    CHECK(jx(doc, "empty.x", &out) == JSON_NONE);
    CHECK(jx(doc, "arr[0]", &out) == JSON_NONE);
    CHECK(jx(doc, "user.tags[3]", &out) == JSON_NONE);
    CHECK(jx(doc, "user.tags[-1]", &out) == JSON_NONE);
    CHECK(jx(doc, "user.tags[x]", &out) == JSON_NONE);
    CHECK(jx(doc, "missing", &out) == JSON_NONE);
    CHECK(jx(doc, "type.sub", &out) == JSON_NONE);
    CHECK(jx(doc, "user.id.x", &out) == JSON_NONE);
    /* keys with escapes */
    CHECK(jx("{\"a\\u0062c\": 1}", "abc", &out) == JSON_NUMBER);
    /* later duplicate keys do not shadow the first */
    CHECK(jx("{\"a\": 1, \"a\": 2}", "a", &out) == JSON_NUMBER && buf_rptr(&out)[0] == '1');
    /* top-level array */
    CHECK(jx("[10, 20]", "[1]", &out) == JSON_NUMBER && memcmp(buf_rptr(&out), "20", 2) == 0);
    /* malformed documents never match and never crash */
    const char *bad[] = { "{", "{\"a\":", "{\"a\" 1}", "{\"a\":1,}", "[1,", "{\"a\":\"unterminated", "nonsense",
                          "{\"a\":{\"b\":[1,2}}", "", "{\"a\":\"\\u12\"}", "{\"a\":\"\\x\"}", NULL };
    for (int i = 0; bad[i]; i++) {
        checks++;
        if (jx(bad[i], "a", &out) != JSON_NONE && jx(bad[i], "a.b", &out) != JSON_NONE) {
            failures++;
            fprintf(stderr, "  FAIL [%s] malformed json %d matched\n", current, i);
        }
    }
    /* nesting is bounded so a hostile body cannot exhaust the stack */
    for (int depth = 100; depth <= 100000; depth *= 10) {
        buf_t deep;
        buf_init(&deep);
        for (int i = 0; i < depth; i++)
            buf_puts(&deep, "{\"a\":");
        buf_puts(&deep, "1");
        for (int i = 0; i < depth; i++)
            buf_puts(&deep, "}");
        buf_append(&deep, "", 1);
        int t = jx(buf_rptr(&deep), "a.a.a", &out);
        CHECK(depth <= 250 ? t == JSON_OBJECT : t == JSON_NONE);
        /* walking the path itself is iterative, so leaf values stay reachable */
        buf_t path;
        buf_init(&path);
        for (int i = 0; i < depth; i++)
            buf_puts(&path, i ? ".a" : "a");
        buf_append(&path, "", 1);
        CHECK(jx(buf_rptr(&deep), buf_rptr(&path), &out) == JSON_NUMBER);
        buf_free(&path);
        buf_free(&deep);
    }
    {
        buf_t arr;
        buf_init(&arr);
        for (int i = 0; i < 5000; i++)
            buf_puts(&arr, "[");
        for (int i = 0; i < 5000; i++)
            buf_puts(&arr, "]");
        buf_append(&arr, "", 1);
        CHECK(jx(buf_rptr(&arr), "", &out) == JSON_NONE);
        CHECK(jx(buf_rptr(&arr), "[0]", &out) == JSON_NONE);
        buf_free(&arr);
    }
    buf_free(&out);
}

/* ------------------------------------------------------------------ */
static config_t *cfg_ok(const char *text)
{
    char err[512];
    config_t *c = config_parse(text, "test", err, sizeof err);
    if (!c) {
        failures++;
        checks++;
        fprintf(stderr, "  FAIL [%s] config rejected: %s\n", current, err);
    }
    return c;
}

static int cfg_bad(const char *text, const char *expect_substr)
{
    char err[512];
    config_t *c = config_parse(text, "test", err, sizeof err);
    checks++;
    if (c) {
        failures++;
        fprintf(stderr, "  FAIL [%s] config accepted but should fail (%s)\n", current, expect_substr);
        config_unref(c);
        return 0;
    }
    if (expect_substr && !strstr(err, expect_substr)) {
        failures++;
        fprintf(stderr, "  FAIL [%s] error '%s' does not mention '%s'\n", current, err, expect_substr);
        return 0;
    }
    return 1;
}

TEST(test_config)
{
    config_t *c = cfg_ok(
        "{\n"
        "  workers 3\n"
        "  admin 127.0.0.1:2019\n"
        "  log_level debug\n"
        "  max_connections 100\n"
        "  grace 3s\n"
        "}\n"
        "# comment\n"
        ":8080, 127.0.0.1:8081 {\n"
        "  max_body 2m\n"
        "  read_timeout 5s\n"
        "  log\n"
        "  route orders {\n"
        "    match method POST\n"
        "    match not path /skip/*\n"
        "    match json type == order refund\n"
        "    match json amount > 10\n"
        "    match header X-T ~ \"^a.c$\"\n"
        "    match query q exists\n"
        "    match remote_ip 10.0.0.0/8\n"
        "    to 127.0.0.1:9001 weight=3 http://127.0.0.1:9002\n"
        "    lb_policy hash json customer.id\n"
        "    lb_retries 1\n"
        "    health_uri /h\n"
        "    header_up X-A \"a b\"\n"
        "    header_up +X-B b\n"
        "    header_down -Server\n"
        "  }\n"
        "  route {\n"
        "    match path /ping\n"
        "    respond 204\n"
        "  }\n"
        "  route r {\n"
        "    redir https://x.example{uri} 308\n"
        "  }\n"
        "  reverse_proxy 127.0.0.1:9003 127.0.0.1:9004 weight=2 {\n"
        "    lb_policy least_conn\n"
        "    max_fails 0\n"
        "    unhealthy_status 5xx\n"
        "    keepalive off\n"
        "  }\n"
        "}\n");
    if (!c)
        return;
    CHECK(c->workers == 3 && c->max_connections == 100 && c->grace == 3 && c->log_level == LOG_DEBUG);
    CHECK_STR(c->admin_addr, "127.0.0.1:2019");
    CHECK(c->nservers == 2 && c->servers[1]->is_admin);
    server_t *s = c->servers[0];
    CHECK(s->naddr == 2);
    CHECK_STR(s->addrs[0], ":8080");
    CHECK_STR(s->addrs[1], "127.0.0.1:8081");
    CHECK(s->max_body == 2u * 1024 * 1024 && s->read_timeout == 5 && s->access_log);
    CHECK(s->nroutes == 4);
    route_t *r = s->routes[0];
    CHECK_STR(r->name, "orders");
    CHECK(r->kind == ROUTE_PROXY && r->nm == 7);
    CHECK(r->m[0].key.src == KS_METHOD && r->m[0].op == OP_EQ && r->m[0].nvals == 1);
    CHECK(r->m[1].key.src == KS_PATH && r->m[1].negate);
    CHECK(r->m[2].key.src == KS_JSON && r->m[2].nvals == 2);
    CHECK_STR(r->m[2].key.name, "type");
    CHECK(r->m[3].op == OP_GT && r->m[3].nums && r->m[3].nums[0] == 10);
    CHECK(r->m[4].op == OP_RE && r->m[4].re != NULL);
    CHECK(r->m[5].op == OP_EXISTS && r->m[5].nvals == 0);
    CHECK(r->m[6].key.src == KS_CLIENT_IP);
    pool_t *p = r->pool;
    CHECK(p->nups == 2 && p->ups[0]->weight == 3 && p->ups[1]->weight == 1 && p->total_weight == 4);
    CHECK_STR(p->ups[0]->hostport, "127.0.0.1:9001");
    CHECK(p->ups[0]->port == 9001 && p->ups[0]->resolved);
    CHECK(p->policy == LB_HASH && p->key.src == KS_JSON);
    CHECK_STR(p->key.name, "customer.id");
    CHECK(p->retries == 1);
    CHECK_STR(p->health_uri, "/h");
    CHECK(p->n_hdr_up == 2 && p->hdr_up[0].kind == 0 && p->hdr_up[1].kind == 1);
    CHECK_STR(p->hdr_up[0].value, "a b");
    CHECK(p->n_hdr_down == 1 && p->hdr_down[0].kind == 2);
    CHECK_STR(p->hdr_down[0].name, "Server");
    CHECK(s->routes[1]->kind == ROUTE_RESPOND && s->routes[1]->resp_status == 204 && s->routes[1]->resp_body == NULL);
    CHECK_STR(s->routes[1]->name, "route2");
    CHECK(s->routes[2]->kind == ROUTE_REDIRECT && s->routes[2]->resp_status == 308);
    CHECK_STR(s->routes[2]->resp_body, "https://x.example{uri}");
    route_t *rp = s->routes[3];
    CHECK(rp->kind == ROUTE_PROXY && rp->nm == 0 && rp->pool->policy == LB_LEAST_CONN);
    CHECK(rp->pool->nups == 2 && rp->pool->ups[1]->weight == 2 && rp->pool->max_fails == 0);
    CHECK(rp->pool->unhealthy_5xx && rp->pool->keepalive_idle == 0);
    CHECK(rp->pool->retries == 1); /* clamped to nups-1 */
    config_ref(c);
    config_unref(c);
    config_unref(c);

    /* policy spellings */
    const char *pols[][2] = {
        { "round_robin", "0" }, { "least_conn", "1" }, { "random", "2" }, { "first", "3" },
        { "ip_hash", "4" }, { "uri_hash", "4" }, { "header X", "4" }, { "cookie c", "4" },
        { "query q", "4" }, { "json a.b", "4" }, { "form f", "4" }, { "body", "4" },
        { "hash json a", "4" }, { "payload form f", "4" }, { "hash client_ip", "4" },
        { NULL, NULL }
    };
    for (int i = 0; pols[i][0]; i++) {
        char text[256];
        snprintf(text, sizeof text, ":1 {\n reverse_proxy 127.0.0.1:1 127.0.0.1:2 {\n  lb_policy %s\n }\n}\n", pols[i][0]);
        config_t *pc = cfg_ok(text);
        if (pc) {
            CHECK(pc->servers[0]->routes[0]->pool->policy == atoi(pols[i][1]));
            config_unref(pc);
        }
    }

    /* errors */
    cfg_bad("", "no server blocks");
    cfg_bad(":1 {\n", "missing '}'");
    cfg_bad(":1 {\n}\n}\n", "unexpected '}'");
    cfg_bad(":1 { reverse_proxy 127.0.0.1:1 }\n", "must end its line");
    cfg_bad(":1 {\n reverse_proxy 127.0.0.1:1 {\n  bogus 1\n }\n}\n", "unknown reverse_proxy option");
    cfg_bad(":1 {\n frobnicate\n}\n", "unknown directive");
    cfg_bad(":1 {\n route {\n  match path /x\n }\n}\n", "no handler");
    cfg_bad(":1 {\n route {\n  to 127.0.0.1:1\n  respond 200\n }\n}\n", "more than one handler");
    cfg_bad(":1 {\n reverse_proxy {\n  lb_policy nope\n }\n}\n", "unknown lb_policy");
    cfg_bad(":1 {\n reverse_proxy 127.0.0.1:1 {\n  lb_policy header\n }\n}\n", "needs a name");
    cfg_bad(":1 {\n reverse_proxy 127.0.0.1:1 {\n  lb_policy round_robin extra\n }\n}\n", "takes no arguments");
    cfg_bad(":1 {\n reverse_proxy {\n }\n}\n", "no upstreams");
    cfg_bad(":1 {\n reverse_proxy weight=2\n}\n", "weight= must follow");
    cfg_bad(":1 {\n reverse_proxy 127.0.0.1:1 weight=abc\n}\n", "invalid weight");
    cfg_bad(":1 {\n reverse_proxy 127.0.0.1:1 weight=0\n}\n", "weight 0");
    c = cfg_ok(":1 {\n reverse_proxy https://127.0.0.1:1 https://localhost:8443 127.0.0.1:2 {\n"
               "  tls_insecure_skip_verify\n  tls_server_name backend.test\n }\n"
               " route {\n  match path /t\n  reverse_proxy 127.0.0.1:3 {\n   transport http {\n    tls\n    tls_insecure_skip_verify\n   }\n  }\n }\n}\n");
    if (c) {
        pool_t *tp = c->servers[0]->routes[0]->pool;
        CHECK(tp->nups == 3 && tp->ups[0]->tls && tp->ups[0]->port == 1 && tp->ups[1]->tls && tp->ups[1]->port == 8443 && !tp->ups[2]->tls);
        CHECK(tp->tls_insecure && tp->client_ctx != NULL);
        CHECK_STR(tp->tls_server_name, "backend.test");
        pool_t *tt = c->servers[0]->routes[1]->pool;
        CHECK(tt->ups[0]->tls && tt->client_ctx != NULL); /* transport http { tls } */
        config_unref(c);
    }
    cfg_bad(":1 {\n reverse_proxy https://127.0.0.1:1 {\n  tls_trusted_ca_certs /no/such/ca.pem\n }\n}\n", "tls_trusted_ca_certs");
    c = cfg_ok(":1 {\n reverse_proxy https://127.0.0.1:1\n}\n");
    if (c) {
        CHECK(c->servers[0]->routes[0]->pool->ups[0]->tls && c->servers[0]->routes[0]->pool->ups[0]->port == 1);
        CHECK(c->servers[0]->routes[0]->pool->client_ctx != NULL);
        config_unref(c);
    }
    cfg_bad(":1 {\n reverse_proxy https://no.such.host.invalid:9\n}\n", "cannot resolve");
    cfg_bad(":1 {\n reverse_proxy 127.0.0.1:99999\n}\n", "invalid upstream address");
    cfg_bad(":1 {\n reverse_proxy no.such.host.invalid:80\n}\n", "cannot resolve");
    cfg_bad(":1 {\n route {\n  match header X ~ \"(\"\n  to 127.0.0.1:1\n }\n}\n", "bad regex");
    cfg_bad(":1 {\n route {\n  match json a > abc\n  to 127.0.0.1:1\n }\n}\n", "not a number");
    cfg_bad(":1 {\n route {\n  match remote_ip 999.1.1.1\n  to 127.0.0.1:1\n }\n}\n", "invalid IP");
    cfg_bad(":1 {\n route {\n  match bogus x\n  to 127.0.0.1:1\n }\n}\n", "unknown match source");
    cfg_bad(":1 {\n route {\n  match header\n  to 127.0.0.1:1\n }\n}\n", "needs a name");
    cfg_bad(":1 {\n route {\n  match path exists /x\n  to 127.0.0.1:1\n }\n}\n", "takes no values");
    cfg_bad(":1 {\n route {\n  match path !=\n  to 127.0.0.1:1\n }\n}\n", "at least one value");
    cfg_bad(":1 {\n max_body lots\n reverse_proxy 127.0.0.1:1\n}\n", "invalid size");
    cfg_bad(":1 {\n read_timeout soon\n reverse_proxy 127.0.0.1:1\n}\n", "invalid duration");
    cfg_bad(":1 {\n tls only-one\n reverse_proxy 127.0.0.1:1\n}\n", "tls accepts");
    {
        /* https without a hostname gets a self-signed certificate */
        config_t *hc = cfg_ok("https://:1 {\n reverse_proxy 127.0.0.1:1\n}\n");
        if (hc) {
            CHECK(hc->servers[0]->tls_mode == TLS_INTERNAL && hc->servers[0]->ssl_ctx != NULL);
            CHECK(hc->nservers == 1); /* no redirect site without hostnames */
            config_unref(hc);
        }
    }
    cfg_bad(":1 {\n tls /no/cert.pem /no/key.pem\n reverse_proxy 127.0.0.1:1\n}\n", "tls");
    cfg_bad("{\n workers many\n}\n:1 {\n reverse_proxy 127.0.0.1:1\n}\n", "invalid number");
    cfg_bad("{\n max_connections 0\n}\n:1 {\n reverse_proxy 127.0.0.1:1\n}\n", "invalid number");
    {
        config_t *mc = cfg_ok("{\n max_connections auto\n}\n:1 {\n reverse_proxy 127.0.0.1:1\n}\n");
        if (mc) {
            CHECK(mc->max_connections == 0); /* 0 = derive from the descriptor limit */
            config_unref(mc);
        }
    }
    cfg_bad("{\n nope 1\n}\n:1 {\n reverse_proxy 127.0.0.1:1\n}\n", "unknown global option");
    cfg_bad(":1 {\n reverse_proxy 127.0.0.1:1\n}\n{\n workers 2\n}\n", "must come first");
    cfg_bad("bad!host {\n reverse_proxy 127.0.0.1:1\n}\n", "invalid hostname");
    cfg_bad(":abc {\n reverse_proxy 127.0.0.1:1\n}\n", "invalid port");
    cfg_bad("example.com, :8080 {\n reverse_proxy 127.0.0.1:1\n}\n", "cannot mix http and https");
    cfg_bad(":1 {\n respond 999\n}\n", "invalid number");
    cfg_bad(":1 {\n reverse_proxy 127.0.0.1:1 {\n  header_up -X-A value\n }\n}\n", "takes no value");
    cfg_bad(":1 {\n reverse_proxy 127.0.0.1:1 {\n  header_up X-A\n }\n}\n", "needs a value");
    cfg_bad(":1 {\n reverse_proxy 127.0.0.1:1 {\n  health_uri nope\n }\n}\n", "must start with '/'");
    cfg_bad(":1 {\n respond 200 \"unterminated\n}\n", "unterminated quoted string");
    /* found by fuzzing: a nameless nested block used to crash the interpreter */
    cfg_bad(":1 {\n route {\n  {\n   match path /x\n  }\n  to 127.0.0.1:1\n }\n}\n", "unexpected '{'");
    cfg_bad(":1 {\n {\n  to 127.0.0.1:1\n }\n}\n", "unexpected '{'");
    cfg_bad("{\n}\n{\n}\n", "must come first");

    /* site addresses: hostnames, implied https, binds and redirect sites */
    c = cfg_ok("{\n auto_https off\n}\n"
               "example.com, www.example.com {\n respond \"a\"\n}\n"
               "http://api.example.com:8080 {\n respond \"b\"\n}\n"
               "localhost {\n respond \"c\"\n}\n"
               "127.0.0.1:9000, [::1]:9000 {\n respond \"d\"\n}\n"
               "*.wild.example {\n respond \"e\"\n}\n");
    if (c) {
        CHECK(c->nservers == 5);
        server_t *a = c->servers[0];
        CHECK(a->tls_mode == TLS_INTERNAL && a->nhosts == 2 && a->naddr == 1 && a->port == 443);
        CHECK_STR(a->addrs[0], ":443");
        CHECK_STR(a->hosts[1], "www.example.com");
        server_t *b = c->servers[1];
        CHECK(b->tls_mode == TLS_NONE && b->port == 8080 && b->nhosts == 1);
        CHECK_STR(b->addrs[0], ":8080");
        server_t *lc = c->servers[2];
        CHECK(lc->tls_mode == TLS_INTERNAL && lc->ssl_ctx != NULL);
        CHECK_STR(lc->hosts[0], "localhost");
        server_t *d = c->servers[3];
        CHECK(d->tls_mode == TLS_NONE && d->nhosts == 0 && d->naddr == 2);
        CHECK_STR(d->addrs[0], "127.0.0.1:9000");
        CHECK_STR(d->addrs[1], "[::1]:9000");
        CHECK_STR(c->servers[4]->hosts[0], "*.wild.example");
        config_unref(c);
    }
    /* with auto https on, an http redirect site is added for https sites */
    c = cfg_ok("{\n http_port 8080\n https_port 8443\n}\n"
               "example.com {\n tls internal\n respond \"a\"\n}\n"
               "other.example {\n tls internal\n respond \"b\"\n}\n"
               "http://other.example {\n respond \"plain\"\n}\n");
    if (c) {
        CHECK(c->http_port == 8080 && c->https_port == 8443);
        CHECK(c->nservers == 4); /* example.com gets a redirect site; other.example already has http */
        CHECK_STR(c->servers[0]->addrs[0], ":8443");
        CHECK(c->servers[0]->port == 8443);
        server_t *redir = c->servers[3];
        CHECK(redir->redirect_https && redir->tls_mode == TLS_NONE && redir->port == 8443);
        CHECK_STR(redir->addrs[0], ":8080");
        CHECK_STR(redir->hosts[0], "example.com");
        CHECK_STR(c->servers[2]->addrs[0], ":8080");
        CHECK(c->servers[2]->tls_mode == TLS_NONE);
        config_unref(c);
    }
    /* tls modes */
    c = cfg_ok(":1 {\n tls internal\n respond ok\n}\n");
    if (c) {
        CHECK(c->servers[0]->tls_mode == TLS_INTERNAL && c->servers[0]->ssl_ctx);
        config_unref(c);
    }
    cfg_bad(":1 {\n tls /no/cert.pem /no/key.pem\n respond ok\n}\n", "cannot load certificate");

    /* env substitution, snippets and imports */
    setenv("LIMER_TEST_PORT", "7777", 1);
    setenv("LIMER_TEST_BODY", "from env", 1);
    c = cfg_ok("(common) {\n  header X-Snippet {args.0}\n}\n"
               ":{$LIMER_TEST_PORT} {\n import common yes\n respond \"{$LIMER_TEST_BODY}\" {$NOPE_UNSET:201}\n}\n");
    if (c) {
        CHECK_STR(c->servers[0]->addrs[0], ":7777");
        CHECK(c->servers[0]->n_hdr_down == 1);
        CHECK_STR(c->servers[0]->hdr_down[0].name, "X-Snippet");
        CHECK_STR(c->servers[0]->hdr_down[0].value, "yes");
        CHECK_STR(c->servers[0]->routes[0]->resp_body, "from env");
        CHECK(c->servers[0]->routes[0]->resp_status == 201);
        config_unref(c);
    }
    cfg_bad(":1 {\n import nope.conf\n respond ok\n}\n", "no such file or snippet");
    {
        FILE *f = fopen("/tmp/limer-unit-import.conf", "w");
        if (f) {
            fputs("respond \"imported\" 202\n", f);
            fclose(f);
            c = cfg_ok(":1 {\n import /tmp/limer-unit-import.conf\n}\n");
            if (c) {
                CHECK(c->servers[0]->nroutes == 1 && c->servers[0]->routes[0]->resp_status == 202);
                CHECK_STR(c->servers[0]->routes[0]->resp_body, "imported");
                config_unref(c);
            }
            unlink("/tmp/limer-unit-import.conf");
        }
    }

    /* server-level header ops, request headers, basic_auth, log, encode */
    c = cfg_ok(":1 {\n header X-A a\n header -Server\n header {\n  +X-B b\n  X-C \"c d\"\n }\n"
               " request_header X-Up up\n basic_auth admin {\n  bob $2b$05$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234\n }\n"
               " log {\n  output stderr\n  format json\n }\n encode gzip zstd {\n  minimum_length 100\n }\n respond ok\n}\n");
    if (c) {
        server_t *s = c->servers[0];
        CHECK(s->n_hdr_down == 4 && s->hdr_down[1].kind == 2 && s->hdr_down[2].kind == 1);
        CHECK_STR(s->hdr_down[3].value, "c d");
        CHECK(s->n_hdr_up == 1);
        CHECK(s->auth && s->auth->nusers == 1);
        CHECK_STR(s->auth->realm, "admin");
        CHECK(s->access_log && s->log_fd == 2 && s->log_json);
        CHECK_STR(s->encode, "gzip zstd");
        CHECK(s->encode_min == 100);
        config_unref(c);
    }
    cfg_bad(":1 {\n basic_auth {\n  bob plaintext\n }\n respond ok\n}\n", "bcrypt hash");
    cfg_bad(":1 {\n encode lzma\n respond ok\n}\n", "encode supports");
    cfg_bad(":1 {\n log {\n  format xml\n }\n respond ok\n}\n", "json or common");

    /* route handlers: rewrite, uri, handle_path, error, abort, respond forms, redir forms */
    c = cfg_ok(":1 {\n"
               " handle_path /api/* {\n  to 127.0.0.1:1\n }\n"
               " handle /old/* {\n  uri strip_prefix /old\n  uri replace .php .html\n  rewrite /new{uri}\n  respond ok\n }\n"
               " route {\n  match path /gone\n  error \"it is gone\" 410\n }\n"
               " route {\n  match path /drop\n  abort\n }\n"
               " route {\n  match path /r\n  redir /elsewhere permanent\n }\n"
               " route {\n  match path /s\n  respond \"body first\" 418\n }\n"
               " error 503\n}\n");
    if (c) {
        server_t *s = c->servers[0];
        CHECK(s->nroutes == 7);
        route_t *hp = s->routes[0];
        CHECK(hp->kind == ROUTE_PROXY && hp->nm == 1 && hp->nrw == 1 && hp->rw[0].kind == RW_STRIP_PREFIX);
        CHECK_STR(hp->rw[0].a, "/api");
        CHECK_STR(hp->m[0].vals[0], "/api/*");
        route_t *h = s->routes[1];
        CHECK(h->nrw == 3 && h->rw[0].kind == RW_STRIP_PREFIX && h->rw[1].kind == RW_REPLACE && h->rw[2].kind == RW_URI);
        CHECK_STR(h->rw[1].b, ".html");
        CHECK(s->routes[2]->kind == ROUTE_ERROR && s->routes[2]->resp_status == 410);
        CHECK_STR(s->routes[2]->resp_body, "it is gone");
        CHECK(s->routes[3]->kind == ROUTE_ABORT);
        CHECK(s->routes[4]->kind == ROUTE_REDIRECT && s->routes[4]->resp_status == 301);
        CHECK(s->routes[5]->kind == ROUTE_RESPOND && s->routes[5]->resp_status == 418);
        CHECK_STR(s->routes[5]->resp_body, "body first");
        CHECK(s->routes[6]->kind == ROUTE_ERROR && s->routes[6]->resp_status == 503 && s->routes[6]->nm == 0);
        config_unref(c);
    }
    cfg_bad(":1 {\n handle_path api/* {\n  respond ok\n }\n}\n", "path pattern like");
    cfg_bad(":1 {\n route {\n  uri strip_prefix\n  respond ok\n }\n}\n", "expects 2 to 3");
    cfg_bad(":1 {\n route {\n  uri frobnicate /x\n  respond ok\n }\n}\n", "uri accepts");
    cfg_bad(":1 {\n route {\n  error oops\n }\n}\n", "needs a status code");
    cfg_bad(":1 {\n route {\n  to 127.0.0.1:1\n  abort\n }\n}\n", "more than one handler");
    cfg_bad(":1 {\n route {\n  file_server\n }\n}\n", "needs a 'root'");
}

/* ------------------------------------------------------------------ */
typedef struct {
    http_req_t req;
    req_ctx_t ctx;
    struct sockaddr_in peer;
} tctx_t;

static void tctx_init(tctx_t *t, const char *raw, const char *ip)
{
    size_t n;
    http_req_init(&t->req);
    int rc = http_parse_request_head(&t->req, raw, strlen(raw), &n);
    if (rc != 1) {
        fprintf(stderr, "  bad fixture request\n");
        abort();
    }
    buf_puts(&t->req.body, raw + n);
    memset(&t->peer, 0, sizeof t->peer);
    t->peer.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &t->peer.sin_addr);
    memset(&t->ctx, 0, sizeof t->ctx);
    t->ctx.req = &t->req;
    t->ctx.peer = (struct sockaddr *)&t->peer;
    t->ctx.peerlen = sizeof t->peer;
    snprintf(t->ctx.peer_ip, sizeof t->ctx.peer_ip, "%s", ip);
}

static int route_from(config_t **cfg_out, const char *match_lines, const req_ctx_t *ctx)
{
    char text[2048];
    snprintf(text, sizeof text, ":1 {\n route {\n%s\n  respond 200\n }\n}\n", match_lines);
    config_t *c = cfg_ok(text);
    if (!c)
        return -1;
    int res = route_matches(c->servers[0]->routes[0], ctx);
    config_unref(c);
    return res;
}

TEST(test_match)
{
    tctx_t t;
    tctx_init(&t,
              "POST /api/orders?region=eu&x=a%20b HTTP/1.1\r\nHost: shop.example.com:8080\r\n"
              "X-Tenant: acme\r\nCookie: a=1; sid=abc; z=2\r\n\r\n"
              "{\"type\":\"order\",\"amount\":150,\"customer\":{\"id\":\"c1\"},\"flag\":null}",
              "10.2.3.4");
    const req_ctx_t *ctx = &t.ctx;
    config_t *c = NULL;

    CHECK(route_from(&c, "  match method POST", ctx) == 1);
    CHECK(route_from(&c, "  match method get", ctx) == 0);
    CHECK(route_from(&c, "  match method GET POST", ctx) == 1);
    CHECK(route_from(&c, "  match path /api/*", ctx) == 1);
    CHECK(route_from(&c, "  match path /api/orders", ctx) == 1);
    CHECK(route_from(&c, "  match path /api", ctx) == 0);
    CHECK(route_from(&c, "  match path ~ ^/api/or", ctx) == 1);
    CHECK(route_from(&c, "  match path !~ ^/api", ctx) == 0);
    CHECK(route_from(&c, "  match not path /api/*", ctx) == 0);
    CHECK(route_from(&c, "  match path ^= /api", ctx) == 1);
    CHECK(route_from(&c, "  match host shop.example.com", ctx) == 1);   /* port stripped */
    CHECK(route_from(&c, "  match host *.example.com", ctx) == 1);
    CHECK(route_from(&c, "  match host other.com", ctx) == 0);
    CHECK(route_from(&c, "  match header X-Tenant acme", ctx) == 1);
    CHECK(route_from(&c, "  match header x-tenant ACME", ctx) == 0);   /* values are case-sensitive */
    CHECK(route_from(&c, "  match header X-Tenant != acme", ctx) == 0);
    CHECK(route_from(&c, "  match header X-Missing != acme", ctx) == 1);
    CHECK(route_from(&c, "  match header X-Missing", ctx) == 0);
    CHECK(route_from(&c, "  match header X-Missing missing", ctx) == 1);
    CHECK(route_from(&c, "  match header X-Tenant exists", ctx) == 1);
    CHECK(route_from(&c, "  match header X-Tenant *= cm", ctx) == 1);
    CHECK(route_from(&c, "  match query region eu", ctx) == 1);
    CHECK(route_from(&c, "  match query x \"a b\"", ctx) == 1);        /* url-decoded */
    CHECK(route_from(&c, "  match query nope", ctx) == 0);
    CHECK(route_from(&c, "  match cookie sid abc", ctx) == 1);
    CHECK(route_from(&c, "  match cookie z 2", ctx) == 1);
    CHECK(route_from(&c, "  match cookie si abc", ctx) == 0);
    CHECK(route_from(&c, "  match json type order", ctx) == 1);
    CHECK(route_from(&c, "  match json type refund order", ctx) == 1);
    CHECK(route_from(&c, "  match json customer.id c1", ctx) == 1);
    CHECK(route_from(&c, "  match json amount > 100", ctx) == 1);
    CHECK(route_from(&c, "  match json amount >= 150", ctx) == 1);
    CHECK(route_from(&c, "  match json amount < 150", ctx) == 0);
    CHECK(route_from(&c, "  match json amount <= 149.9", ctx) == 0);
    CHECK(route_from(&c, "  match json type > 5", ctx) == 0);           /* non-numeric never compares */
    CHECK(route_from(&c, "  match json flag exists", ctx) == 0);        /* null counts as absent */
    CHECK(route_from(&c, "  match json missing missing", ctx) == 1);
    CHECK(route_from(&c, "  match body ~ \"\\\"amount\\\":150\"", ctx) == 1);
    CHECK(route_from(&c, "  match body *= customer", ctx) == 1);
    CHECK(route_from(&c, "  match remote_ip 10.0.0.0/8", ctx) == 1);
    CHECK(route_from(&c, "  match remote_ip 10.2.3.4", ctx) == 1);
    CHECK(route_from(&c, "  match remote_ip 192.168.0.0/16 10.2.0.0/16", ctx) == 1);
    CHECK(route_from(&c, "  match remote_ip != 10.0.0.0/8", ctx) == 0);
    CHECK(route_from(&c, "  match not remote_ip 10.0.0.0/8", ctx) == 0);
    CHECK(route_from(&c, "  match remote_ip ~ \"^10[.]2\"", ctx) == 1);
    CHECK(route_from(&c, "  match uri *= region=eu", ctx) == 1);
    /* AND semantics */
    CHECK(route_from(&c, "  match method POST\n  match json type order\n  match header X-Tenant acme", ctx) == 1);
    CHECK(route_from(&c, "  match method POST\n  match json type refund", ctx) == 0);

    /* key extraction */
    buf_t out;
    buf_init(&out);
    keysrc_t k = { KS_FORM, (char *)"b" };
    tctx_t f;
    tctx_init(&f, "POST / HTTP/1.1\r\n\r\na=1&b=two%20words&c", "1.1.1.1");
    CHECK(key_extract(&k, &f.ctx, &out) == 1 && buf_readable(&out) == 9 && memcmp(buf_rptr(&out), "two words", 9) == 0);
    k.name = (char *)"c";
    CHECK(key_extract(&k, &f.ctx, &out) == 1 && buf_readable(&out) == 0);
    k.name = (char *)"d";
    CHECK(key_extract(&k, &f.ctx, &out) == 0);
    k.src = KS_BODY;
    CHECK(key_extract(&k, &f.ctx, &out) == 1 && buf_readable(&out) == strlen("a=1&b=two%20words&c"));
    k.src = KS_CLIENT_IP;
    CHECK(key_extract(&k, &f.ctx, &out) == 1 && memcmp(buf_rptr(&out), "1.1.1.1", 7) == 0);
    k.src = KS_HOST;
    CHECK(key_extract(&k, &f.ctx, &out) == 0);
    k.src = KS_JSON; k.name = (char *)"x";
    CHECK(key_extract(&k, &f.ctx, &out) == 0);
    k.src = KS_PATH;
    CHECK(key_extract(&k, ctx, &out) == 1 && memcmp(buf_rptr(&out), "/api/orders", 11) == 0);
    buf_free(&out);
    http_req_free(&f.req);
    http_req_free(&t.req);
}

/* ------------------------------------------------------------------ */
static pool_t *mkpool(config_t **cfg, const char *policy, const char *ups)
{
    char text[512];
    snprintf(text, sizeof text, ":1 {\n reverse_proxy %s {\n  lb_policy %s\n  max_fails 2\n  fail_timeout 5s\n }\n}\n", ups, policy);
    *cfg = cfg_ok(text);
    return *cfg ? (*cfg)->servers[0]->routes[0]->pool : NULL;
}

TEST(test_balance)
{
    config_t *c;
    int idx;
    char why[128];

    pool_t *p = mkpool(&c, "round_robin", "127.0.0.1:1 weight=3 127.0.0.1:2 weight=1");
    if (!p) return;
    int counts[2] = { 0, 0 };
    char seq[9] = "";
    for (int i = 0; i < 8; i++) {
        upstream_t *u = pool_select(p, NULL, 0, 0, &idx, why, sizeof why);
        CHECK(u != NULL);
        counts[idx]++;
        seq[i] = (char)('0' + idx);
    }
    CHECK(counts[0] == 6 && counts[1] == 2);
    CHECK_STR(seq, "00100010"); /* smooth: the light upstream is interleaved, not bunched */
    /* unhealthy upstreams are skipped; passive failure marks them down */
    upstream_report_failure(p, p->ups[0], 100, "test");
    CHECK(upstream_healthy(p->ups[0], 100));
    upstream_report_failure(p, p->ups[0], 100, "test");
    CHECK(!upstream_healthy(p->ups[0], 100) && p->ups[0]->fail_until == 105);
    for (int i = 0; i < 4; i++)
        CHECK(pool_select(p, NULL, 0, 100, &idx, NULL, 0) == p->ups[1]);
    CHECK(upstream_healthy(p->ups[0], 105.1));
    upstream_report_success(p, p->ups[0]);
    CHECK(p->ups[0]->fails == 0);
    /* tried mask excludes upstreams; nothing left -> NULL */
    CHECK(pool_select(p, NULL, 0x3, 200, &idx, NULL, 0) == NULL);
    p->ups[1]->hc_status = -1;
    CHECK(pool_select(p, NULL, 0x1, 200, &idx, NULL, 0) == NULL);
    config_unref(c);

    p = mkpool(&c, "first", "127.0.0.1:1 127.0.0.1:2 127.0.0.1:3");
    if (!p) return;
    CHECK(pool_select(p, NULL, 0, 0, &idx, NULL, 0) == p->ups[0]);
    CHECK(pool_select(p, NULL, 0x1, 0, &idx, NULL, 0) == p->ups[1]);
    p->ups[0]->hc_status = -1;
    CHECK(pool_select(p, NULL, 0, 0, &idx, NULL, 0) == p->ups[1]);
    config_unref(c);

    p = mkpool(&c, "least_conn", "127.0.0.1:1 127.0.0.1:2 weight=2");
    if (!p) return;
    p->ups[0]->active = 2;
    p->ups[1]->active = 3; /* 3/2 = 1.5 < 2 */
    CHECK(pool_select(p, NULL, 0, 0, &idx, NULL, 0) == p->ups[1]);
    p->ups[1]->active = 5;
    CHECK(pool_select(p, NULL, 0, 0, &idx, NULL, 0) == p->ups[0]);
    config_unref(c);

    p = mkpool(&c, "random", "127.0.0.1:1 127.0.0.1:2 127.0.0.1:3");
    if (!p) return;
    int seen[3] = { 0, 0, 0 };
    for (int i = 0; i < 300; i++) {
        CHECK(pool_select(p, NULL, 0, 0, &idx, NULL, 0) != NULL);
        seen[idx]++;
    }
    CHECK(seen[0] > 50 && seen[1] > 50 && seen[2] > 50);
    config_unref(c);

    /* hashing: sticky, spreads, moves minimal keys when an upstream dies */
    p = mkpool(&c, "hash header X-Key", "127.0.0.1:1 127.0.0.1:2 127.0.0.1:3 127.0.0.1:4");
    if (!p) return;
    int assign[200];
    int dist[4] = { 0, 0, 0, 0 };
    for (int i = 0; i < 200; i++) {
        char raw[128];
        snprintf(raw, sizeof raw, "GET / HTTP/1.1\r\nX-Key: key-%d\r\n\r\n", i);
        tctx_t t;
        tctx_init(&t, raw, "1.2.3.4");
        upstream_t *u = pool_select(p, &t.ctx, 0, 0, &idx, why, sizeof why);
        CHECK(u != NULL);
        assign[i] = idx;
        dist[idx]++;
        if (i == 0)
            CHECK(strstr(why, "hash(header:X-Key=key-0)") != NULL);
        for (int k = 0; k < 3; k++) {
            int idx2;
            CHECK(pool_select(p, &t.ctx, 0, 0, &idx2, NULL, 0) == u && idx2 == idx);
        }
        http_req_free(&t.req);
    }
    CHECK(dist[0] > 25 && dist[1] > 25 && dist[2] > 25 && dist[3] > 25);
    p->ups[1]->hc_status = -1;
    int moved = 0;
    for (int i = 0; i < 200; i++) {
        char raw[128];
        snprintf(raw, sizeof raw, "GET / HTTP/1.1\r\nX-Key: key-%d\r\n\r\n", i);
        tctx_t t;
        tctx_init(&t, raw, "1.2.3.4");
        pool_select(p, &t.ctx, 0, 0, &idx, NULL, 0);
        CHECK(idx != 1);
        if (assign[i] != 1 && idx != assign[i])
            moved++;
        http_req_free(&t.req);
    }
    CHECK(moved == 0); /* only the dead upstream's keys are reassigned */
    /* missing key falls back to round robin and says so */
    tctx_t nokey;
    tctx_init(&nokey, "GET / HTTP/1.1\r\n\r\n", "1.2.3.4");
    CHECK(pool_select(p, &nokey.ctx, 0, 0, &idx, why, sizeof why) != NULL);
    CHECK(strstr(why, "key missing") != NULL);
    http_req_free(&nokey.req);
    config_unref(c);

    /* weighted hashing favours the heavier upstream */
    p = mkpool(&c, "hash client_ip", "127.0.0.1:1 weight=1 127.0.0.1:2 weight=4");
    if (!p) return;
    int w[2] = { 0, 0 };
    for (int i = 0; i < 500; i++) {
        char ip[32];
        snprintf(ip, sizeof ip, "10.%d.%d.%d", i / 65536, (i / 256) % 256, i % 256);
        tctx_t t;
        tctx_init(&t, "GET / HTTP/1.1\r\n\r\n", ip);
        pool_select(p, &t.ctx, 0, 0, &idx, NULL, 0);
        w[idx]++;
        http_req_free(&t.req);
    }
    CHECK(w[1] > 3 * w[0]);
    config_unref(c);
    CHECK_STR(lb_policy_name(LB_HASH), "hash");
    CHECK_STR(keysrc_name(KS_JSON), "json");
}

/* ------------------------------------------------------------------ */
TEST(test_ratelimit)
{
    ratelimit_t *rl = ratelimit_new(2.0, 3.0, 4);
    double retry = 0;
    /* burst of 3, then limited */
    CHECK(ratelimit_check(rl, "a", 100.0, &retry) == 1);
    CHECK(ratelimit_check(rl, "a", 100.0, &retry) == 1);
    CHECK(ratelimit_check(rl, "a", 100.0, &retry) == 1);
    CHECK(ratelimit_check(rl, "a", 100.0, &retry) == 0 && retry > 0.49 && retry < 0.51);
    /* independent keys */
    CHECK(ratelimit_check(rl, "b", 100.0, &retry) == 1);
    /* refill: 0.5s -> one token */
    CHECK(ratelimit_check(rl, "a", 100.5, &retry) == 1);
    CHECK(ratelimit_check(rl, "a", 100.5, &retry) == 0);
    /* never exceeds burst after a long idle */
    CHECK(ratelimit_check(rl, "a", 1000.0, &retry) == 1);
    CHECK(ratelimit_check(rl, "a", 1000.0, &retry) == 1);
    CHECK(ratelimit_check(rl, "a", 1000.0, &retry) == 1);
    CHECK(ratelimit_check(rl, "a", 1000.0, &retry) == 0);
    /* table cap: more keys than max_keys evicts idle ones, service continues */
    for (int i = 0; i < 50; i++) {
        char k[16];
        snprintf(k, sizeof k, "k%d", i);
        CHECK(ratelimit_check(rl, k, 2000.0 + i, &retry) == 1);
    }
    uint64_t hits, limited;
    int keys;
    ratelimit_stats(rl, &hits, &limited, &keys);
    CHECK(keys <= 4 && hits == 61 && limited == 3);
    CHECK(ratelimit_rate(rl) == 2.0);
    ratelimit_free(rl);

    /* config forms */
    config_t *c = cfg_ok(":1 {\n rate_limit 5r/s\n route {\n  match path /x\n  rate_limit zone1 {\n   key {header.X-Key}\n   rate 120r/m\n   burst 10\n   status 503\n   max_keys 50\n  }\n  respond ok\n }\n}\n");
    if (c) {
        server_t *s = c->servers[0];
        CHECK(s->rl && s->rl->rate == 5 && s->rl->burst == 5 && s->rl->status == 429);
        CHECK_STR(s->rl->key, "{remote_ip}");
        rate_limit_cfg_t *r = s->routes[0]->rl;
        CHECK(r && r->rate == 2 && r->burst == 10 && r->status == 503 && r->max_keys == 50);
        CHECK_STR(r->name, "zone1");
        CHECK_STR(r->key, "{header.X-Key}");
        config_unref(c);
    }
    cfg_bad(":1 {\n rate_limit {\n  key {remote_ip}\n }\n respond ok\n}\n", "needs a rate");
    cfg_bad(":1 {\n rate_limit {\n  rate fast\n }\n respond ok\n}\n", "invalid rate");
    cfg_bad(":1 {\n rate_limit 1r/s {\n  bogus 1\n }\n respond ok\n}\n", "unknown rate_limit option");

    /* sticky cookie policy */
    c = cfg_ok(":1 {\n reverse_proxy 127.0.0.1:1 127.0.0.1:2 {\n  lb_policy sticky_cookie sess\n }\n}\n");
    if (c) {
        pool_t *p = c->servers[0]->routes[0]->pool;
        CHECK(p->policy == LB_STICKY && p->key.src == KS_COOKIE);
        CHECK_STR(p->key.name, "sess");
        CHECK(strlen(p->ups[0]->sticky_id) == 16 && strcmp(p->ups[0]->sticky_id, p->ups[1]->sticky_id) != 0);
        /* selection follows the cookie, falls back otherwise */
        tctx_t t;
        char raw[128];
        snprintf(raw, sizeof raw, "GET / HTTP/1.1\r\nCookie: sess=%s\r\n\r\n", p->ups[1]->sticky_id);
        tctx_init(&t, raw, "1.1.1.1");
        int idx;
        char why[64];
        CHECK(pool_select(p, &t.ctx, 0, 0, &idx, why, sizeof why) == p->ups[1] && strcmp(why, "sticky_cookie") == 0);
        p->ups[1]->drained = 1;
        CHECK(pool_select(p, &t.ctx, 0, 0, &idx, why, sizeof why) == p->ups[0]); /* drained -> reassigned */
        CHECK(strstr(why, "new") != NULL);
        http_req_free(&t.req);
        config_unref(c);
    }
}

/* ------------------------------------------------------------------ */
int main(void)
{
    log_level = LOG_ERROR;
    test_buf_run();
    test_util_run();
    test_http_request_run();
    test_http_response_run();
    test_chunked_run();
    test_json_run();
    test_config_run();
    test_match_run();
    test_balance_run();
    test_ratelimit_run();
    printf("unit tests: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
