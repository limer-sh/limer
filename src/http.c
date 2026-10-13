/* http.c - HTTP/1.x head parsing and chunked transfer coding */
#include "limer.h"
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void http_req_init(http_req_t *r)
{
    memset(r, 0, sizeof *r);
    r->content_length = -1;
    buf_init(&r->body);
}

void http_req_free(http_req_t *r)
{
    free(r->raw);
    free(r->path);
    free(r->query);
    buf_free(&r->body);
    http_req_init(r);
}

void http_resp_init(http_resp_t *r)
{
    memset(r, 0, sizeof *r);
    r->content_length = -1;
}

void http_resp_free(http_resp_t *r)
{
    free(r->raw);
    http_resp_init(r);
}

const char *http_hdr_get(const hdr_t *h, int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (strcasecmp(h[i].name, name) == 0)
            return h[i].value;
    return NULL;
}

int http_hdr_is_hop_by_hop(const char *name)
{
    static const char *hop[] = {
        "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
        "Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade", NULL
    };
    for (int i = 0; hop[i]; i++)
        if (strcasecmp(name, hop[i]) == 0)
            return 1;
    return 0;
}

/* Does the comma-separated Connection header value contain `token`? */
int http_hdr_connection_has(const char *v, const char *token)
{
    if (!v)
        return 0;
    size_t tl = strlen(token);
    const char *p = v;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',')
            p++;
        const char *start = p;
        while (*p && *p != ',' && *p != ' ' && *p != '\t')
            p++;
        if ((size_t)(p - start) == tl && strncasecmp(start, token, tl) == 0)
            return 1;
    }
    return 0;
}

const char *http_status_reason(int s)
{
    switch (s) {
    case 100: return "Continue";
    case 101: return "Switching Protocols";
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 413: return "Payload Too Large";
    case 414: return "URI Too Long";
    case 415: return "Unsupported Media Type";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return "Unknown";
    }
}

/* Find end of head ("\r\n\r\n" or "\n\n"). Returns head length incl. terminator, 0 if incomplete. */
static size_t find_head_end(const char *data, size_t len)
{
    for (size_t i = 0; i + 1 < len; i++) {
        if (data[i] == '\n') {
            if (data[i + 1] == '\n')
                return i + 2;
            if (i + 2 < len && data[i + 1] == '\r' && data[i + 2] == '\n')
                return i + 3;
        }
    }
    return 0;
}

static int valid_token(const char *s, size_t n)
{
    if (n == 0)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 32 || c >= 127 || strchr("()<>@,;:\\\"/[]?={}", c))
            return 0;
    }
    return 1;
}

static int valid_field_name(const char *s)
{
    return valid_token(s, strlen(s));
}

/* Parse header lines starting at `p` (NUL-terminated, lines end in \n). */
static int parse_header_lines(char *p, hdr_t *hdrs, int *nhdr)
{
    int n = 0;
    while (*p) {
        char *eol = strchr(p, '\n');
        if (!eol)
            break;
        char *next = eol + 1;
        if (eol > p && eol[-1] == '\r')
            eol--;
        *eol = 0;
        if (eol == p) {
            p = next;
            break;
        }
        if (*p == ' ' || *p == '\t') {
            /* obsolete line folding: reject for safety */
            return -1;
        }
        char *colon = strchr(p, ':');
        if (!colon || colon == p)
            return -1;
        *colon = 0;
        if (!valid_field_name(p))
            return -1;
        char *v = colon + 1;
        while (*v == ' ' || *v == '\t')
            v++;
        char *vend = v + strlen(v);
        while (vend > v && (vend[-1] == ' ' || vend[-1] == '\t'))
            *--vend = 0;
        if (n >= HTTP_MAX_HEADERS)
            return -1;
        hdrs[n].name = p;
        hdrs[n].value = v;
        n++;
        p = next;
    }
    *nhdr = n;
    return 0;
}

static int parse_content_length(const char *v, int64_t *out)
{
    if (!*v)
        return -1;
    for (const char *p = v; *p; p++)
        if (!isdigit((unsigned char)*p))
            return -1;
    errno = 0;
    char *end;
    long long n = strtoll(v, &end, 10);
    if (errno || n < 0)
        return -1;
    *out = n;
    return 0;
}

/* Common framing logic: Content-Length / Transfer-Encoding. Returns -1 on conflict. */
static int framing(hdr_t *hdrs, int nhdr, int64_t *clen, int *chunked)
{
    *clen = -1;
    *chunked = 0;
    int seen_cl = 0;
    for (int i = 0; i < nhdr; i++) {
        if (strcasecmp(hdrs[i].name, "Transfer-Encoding") == 0) {
            /* Only the exact coding "chunked" is supported. Anything else
             * (unknown codings, "gzip, chunked", repeated headers) is rejected
             * so both ends always agree on where a message ends. */
            if (*chunked || strcasecmp(hdrs[i].value, "chunked") != 0)
                return -1;
            *chunked = 1;
        } else if (strcasecmp(hdrs[i].name, "Content-Length") == 0) {
            int64_t n;
            if (parse_content_length(hdrs[i].value, &n) < 0)
                return -1;
            if (seen_cl && n != *clen)
                return -1;
            seen_cl = 1;
            *clen = n;
        }
    }
    if (*chunked && seen_cl)
        return -1; /* request smuggling vector: reject */
    return 0;
}

int http_parse_request_head(http_req_t *r, const char *data, size_t len, size_t *consumed)
{
    /* skip leading CRLFs (RFC 7230 3.5) */
    size_t skip = 0;
    while (skip < len && (data[skip] == '\r' || data[skip] == '\n'))
        skip++;
    data += skip;
    len -= skip;
    size_t hl = find_head_end(data, len);
    if (!hl) {
        if (len > HTTP_MAX_HEAD)
            return -2;
        return 0;
    }
    if (hl > HTTP_MAX_HEAD)
        return -2;
    if (memchr(data, 0, hl))
        return -1; /* NUL bytes are never valid in a message head */

    r->raw = xstrndup(data, hl);
    r->raw_len = hl;
    char *p = r->raw;
    char *eol = strchr(p, '\n');
    char *next = eol + 1;
    if (eol > p && eol[-1] == '\r')
        eol--;
    *eol = 0;

    /* request line: METHOD SP target SP HTTP/1.x */
    char *sp1 = strchr(p, ' ');
    if (!sp1)
        return -1;
    *sp1 = 0;
    char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2)
        return -1;
    *sp2 = 0;
    r->method = p;
    r->uri = sp1 + 1;
    const char *ver = sp2 + 1;
    if (!valid_token(r->method, strlen(r->method)) || !*r->uri)
        return -1;
    if (strncmp(ver, "HTTP/1.", 7) != 0 || !isdigit((unsigned char)ver[7]) || ver[8])
        return -1;
    r->minor = ver[7] - '0';
    for (const char *u = r->uri; *u; u++)
        if ((unsigned char)*u <= 32 || (unsigned char)*u >= 127)
            return -1;

    if (parse_header_lines(next, r->hdrs, &r->nhdr) < 0)
        return -1;
    if (framing(r->hdrs, r->nhdr, &r->content_length, &r->chunked) < 0)
        return -1;

    /* split path / query. Absolute-form targets: strip scheme://host */
    const char *target = r->uri;
    if (str_has_prefix(target, "http://") || str_has_prefix(target, "https://")) {
        const char *s = strchr(target + 8, '/');
        target = s ? s : "/";
    }
    const char *q = strchr(target, '?');
    if (q) {
        r->path = xstrndup(target, (size_t)(q - target));
        r->query = xstrdup(q + 1);
    } else {
        r->path = xstrdup(target);
        r->query = xstrdup("");
    }

    const char *conn = http_hdr_get(r->hdrs, r->nhdr, "Connection");
    if (r->minor >= 1)
        r->keep_alive = !http_hdr_connection_has(conn, "close");
    else
        r->keep_alive = http_hdr_connection_has(conn, "keep-alive");
    r->upgrade = http_hdr_connection_has(conn, "upgrade") && http_hdr_get(r->hdrs, r->nhdr, "Upgrade") != NULL;
    const char *expect = http_hdr_get(r->hdrs, r->nhdr, "Expect");
    r->expect_100 = expect && strcasecmp(expect, "100-continue") == 0;

    *consumed = skip + hl;
    return 1;
}

int http_parse_response_head(http_resp_t *r, const char *data, size_t len, size_t *consumed)
{
    size_t hl = find_head_end(data, len);
    if (!hl) {
        if (len > HTTP_MAX_HEAD)
            return -2;
        return 0;
    }
    if (hl > HTTP_MAX_HEAD)
        return -2;
    if (memchr(data, 0, hl))
        return -1;
    r->raw = xstrndup(data, hl);
    r->raw_len = hl;
    char *p = r->raw;
    char *eol = strchr(p, '\n');
    char *next = eol + 1;
    if (eol > p && eol[-1] == '\r')
        eol--;
    *eol = 0;

    /* status line: HTTP/1.x SP 3DIGIT [SP reason] */
    if (strncmp(p, "HTTP/1.", 7) != 0 || !isdigit((unsigned char)p[7]) || p[8] != ' ')
        return -1;
    r->minor = p[7] - '0';
    const char *st = p + 9;
    if (!isdigit((unsigned char)st[0]) || !isdigit((unsigned char)st[1]) || !isdigit((unsigned char)st[2]))
        return -1;
    r->status = (st[0] - '0') * 100 + (st[1] - '0') * 10 + (st[2] - '0');
    if (st[3] == ' ')
        r->reason = (char *)st + 4;
    else if (st[3] == 0)
        r->reason = (char *)"";
    else
        return -1;

    if (parse_header_lines(next, r->hdrs, &r->nhdr) < 0)
        return -1;
    if (framing(r->hdrs, r->nhdr, &r->content_length, &r->chunked) < 0)
        return -1;
    const char *conn = http_hdr_get(r->hdrs, r->nhdr, "Connection");
    if (r->minor >= 1)
        r->keep_alive = !http_hdr_connection_has(conn, "close");
    else
        r->keep_alive = http_hdr_connection_has(conn, "keep-alive");
    *consumed = hl;
    return 1;
}

/* Chunked coding scanner states */
enum {
    CH_SIZE = 0,     /* reading hex size digits            */
    CH_EXT,          /* skipping a chunk extension to EOL  */
    CH_SIZE_LF,      /* saw CR after size, expect LF       */
    CH_DATA,         /* copying chunk payload              */
    CH_DATA_CR,      /* expect CR or LF after payload      */
    CH_DATA_LF,      /* expect LF after CR                 */
    CH_TRAILER,      /* at start of a trailer line         */
    CH_TRAILER_LINE, /* skipping a trailer line to LF      */
    CH_TRAILER_LF,   /* saw CR on empty trailer line       */
    CH_DONE
};

static int chunk_size_done(chunk_state_t *cs)
{
    if (cs->ndigits == 0)
        return -1;
    cs->ndigits = 0;
    cs->st = cs->remaining == 0 ? CH_TRAILER : CH_DATA;
    return 0;
}

int http_chunk_scan(chunk_state_t *cs, const char *in, size_t len, size_t *consumed, buf_t *out)
{
    size_t i = 0;
    while (i < len && cs->st != CH_DONE) {
        unsigned char c = (unsigned char)in[i];
        switch (cs->st) {
        case CH_SIZE:
            if (isxdigit(c)) {
                int v = isdigit(c) ? c - '0' : (tolower(c) - 'a' + 10);
                if (cs->remaining > (SIZE_MAX >> 5) || cs->ndigits > 16)
                    return -1;
                cs->remaining = (cs->remaining << 4) | (size_t)v;
                cs->ndigits++;
                i++;
            } else if (c == ';' || c == ' ' || c == '\t') {
                if (cs->ndigits == 0)
                    return -1;
                cs->st = CH_EXT;
                i++;
            } else if (c == '\r') {
                if (cs->ndigits == 0)
                    return -1;
                cs->st = CH_SIZE_LF;
                i++;
            } else if (c == '\n') {
                if (chunk_size_done(cs) < 0)
                    return -1;
                i++;
            } else {
                return -1;
            }
            break;
        case CH_EXT:
            if (c == '\r') {
                cs->st = CH_SIZE_LF;
            } else if (c == '\n') {
                if (chunk_size_done(cs) < 0)
                    return -1;
            }
            i++;
            break;
        case CH_SIZE_LF:
            if (c != '\n')
                return -1;
            if (chunk_size_done(cs) < 0)
                return -1;
            i++;
            break;
        case CH_DATA: {
            size_t take = len - i;
            if (take > cs->remaining)
                take = cs->remaining;
            if (out && buf_append(out, in + i, take) < 0)
                return -1;
            i += take;
            cs->remaining -= take;
            if (cs->remaining == 0)
                cs->st = CH_DATA_CR;
            break;
        }
        case CH_DATA_CR:
            if (c == '\r')
                cs->st = CH_DATA_LF;
            else if (c == '\n')
                cs->st = CH_SIZE;
            else
                return -1;
            i++;
            break;
        case CH_DATA_LF:
            if (c != '\n')
                return -1;
            cs->st = CH_SIZE;
            i++;
            break;
        case CH_TRAILER:
            if (c == '\r')
                cs->st = CH_TRAILER_LF;
            else if (c == '\n')
                cs->st = CH_DONE;
            else
                cs->st = CH_TRAILER_LINE;
            i++;
            break;
        case CH_TRAILER_LINE:
            if (c == '\n')
                cs->st = CH_TRAILER;
            i++;
            break;
        case CH_TRAILER_LF:
            if (c != '\n')
                return -1;
            cs->st = CH_DONE;
            i++;
            break;
        default:
            return -1;
        }
    }
    *consumed = i;
    if (cs->st == CH_DONE)
        cs->done = 1;
    return 0;
}
