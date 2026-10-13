/* json.c - minimal JSON scanner for dotted-path value extraction */
#include "limer.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* Nesting deeper than this is treated as malformed: the skipper is recursive
 * and an attacker-controlled body must not be able to exhaust the stack. */
#define JSON_MAX_DEPTH 256

typedef struct {
    const char *p;
    const char *end;
    int depth;
} js_t;

static void skip_ws(js_t *j)
{
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r'))
        j->p++;
}

/* Skip a JSON string starting at '"'. Returns 0 on success. */
static int skip_string(js_t *j)
{
    if (j->p >= j->end || *j->p != '"')
        return -1;
    j->p++;
    while (j->p < j->end) {
        char c = *j->p++;
        if (c == '\\') {
            if (j->p >= j->end)
                return -1;
            j->p++;
        } else if (c == '"') {
            return 0;
        }
    }
    return -1;
}

static int skip_value(js_t *j);

static int skip_container(js_t *j, char open, char close)
{
    if (j->p >= j->end || *j->p != open)
        return -1;
    if (++j->depth > JSON_MAX_DEPTH)
        return -1;
    j->p++;
    skip_ws(j);
    if (j->p < j->end && *j->p == close) {
        j->p++;
        j->depth--;
        return 0;
    }
    for (;;) {
        skip_ws(j);
        if (open == '{') {
            if (skip_string(j) < 0)
                return -1;
            skip_ws(j);
            if (j->p >= j->end || *j->p != ':')
                return -1;
            j->p++;
            skip_ws(j);
        }
        if (skip_value(j) < 0)
            return -1;
        skip_ws(j);
        if (j->p >= j->end)
            return -1;
        if (*j->p == ',') {
            j->p++;
            continue;
        }
        if (*j->p == close) {
            j->p++;
            j->depth--;
            return 0;
        }
        return -1;
    }
}

static int skip_value(js_t *j)
{
    skip_ws(j);
    if (j->p >= j->end)
        return -1;
    char c = *j->p;
    if (c == '"')
        return skip_string(j);
    if (c == '{')
        return skip_container(j, '{', '}');
    if (c == '[')
        return skip_container(j, '[', ']');
    /* literal: number, true, false, null */
    const char *s = j->p;
    while (j->p < j->end && (isalnum((unsigned char)*j->p) || *j->p == '-' || *j->p == '+' || *j->p == '.'))
        j->p++;
    return j->p > s ? 0 : -1;
}

static void put_utf8(buf_t *out, unsigned cp)
{
    char b[4];
    int n;
    if (cp < 0x80) {
        b[0] = (char)cp;
        n = 1;
    } else if (cp < 0x800) {
        b[0] = (char)(0xC0 | (cp >> 6));
        b[1] = (char)(0x80 | (cp & 0x3F));
        n = 2;
    } else if (cp < 0x10000) {
        b[0] = (char)(0xE0 | (cp >> 12));
        b[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        b[2] = (char)(0x80 | (cp & 0x3F));
        n = 3;
    } else {
        b[0] = (char)(0xF0 | (cp >> 18));
        b[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        b[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        b[3] = (char)(0x80 | (cp & 0x3F));
        n = 4;
    }
    buf_append(out, b, (size_t)n);
}

static int hex4(const char *p, const char *end, unsigned *out)
{
    if (end - p < 4)
        return -1;
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9')
            v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v |= (unsigned)(c - 'A' + 10);
        else
            return -1;
    }
    *out = v;
    return 0;
}

/* Decode the string at j->p (which must be '"') into out. */
static int decode_string(js_t *j, buf_t *out)
{
    if (j->p >= j->end || *j->p != '"')
        return -1;
    j->p++;
    while (j->p < j->end) {
        char c = *j->p++;
        if (c == '"')
            return 0;
        if (c != '\\') {
            buf_append(out, &c, 1);
            continue;
        }
        if (j->p >= j->end)
            return -1;
        char e = *j->p++;
        switch (e) {
        case '"': buf_append(out, "\"", 1); break;
        case '\\': buf_append(out, "\\", 1); break;
        case '/': buf_append(out, "/", 1); break;
        case 'b': buf_append(out, "\b", 1); break;
        case 'f': buf_append(out, "\f", 1); break;
        case 'n': buf_append(out, "\n", 1); break;
        case 'r': buf_append(out, "\r", 1); break;
        case 't': buf_append(out, "\t", 1); break;
        case 'u': {
            unsigned cp;
            if (hex4(j->p, j->end, &cp) < 0)
                return -1;
            j->p += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF && j->end - j->p >= 6 && j->p[0] == '\\' && j->p[1] == 'u') {
                unsigned lo;
                if (hex4(j->p + 2, j->end, &lo) == 0 && lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    j->p += 6;
                }
            }
            put_utf8(out, cp);
            break;
        }
        default:
            return -1;
        }
    }
    return -1;
}

/* Compare the JSON string at j->p with key (raw compare, handles simple escapes by decoding). */
static int key_equals(js_t *j, const char *key, size_t keylen)
{
    buf_t tmp;
    buf_init(&tmp);
    js_t save = *j;
    int eq = 0;
    if (decode_string(j, &tmp) == 0)
        eq = buf_readable(&tmp) == keylen && (keylen == 0 || memcmp(buf_rptr(&tmp), key, keylen) == 0);
    else
        *j = save;
    buf_free(&tmp);
    return eq;
}

/* Position j at the value for object member `key`. */
static int descend_object(js_t *j, const char *key, size_t keylen)
{
    skip_ws(j);
    if (j->p >= j->end || *j->p != '{')
        return -1;
    j->p++;
    skip_ws(j);
    if (j->p < j->end && *j->p == '}')
        return -1;
    for (;;) {
        skip_ws(j);
        js_t ks = *j;
        if (ks.p >= ks.end || *ks.p != '"')
            return -1;
        int match = key_equals(&ks, key, keylen);
        if (!match) {
            if (skip_string(j) < 0)
                return -1;
        } else {
            *j = ks;
        }
        skip_ws(j);
        if (j->p >= j->end || *j->p != ':')
            return -1;
        j->p++;
        skip_ws(j);
        if (match)
            return 0;
        if (skip_value(j) < 0)
            return -1;
        skip_ws(j);
        if (j->p >= j->end)
            return -1;
        if (*j->p == ',') {
            j->p++;
            continue;
        }
        return -1; /* '}' reached: not found */
    }
}

/* Position j at array element `idx`. */
static int descend_array(js_t *j, long idx)
{
    skip_ws(j);
    if (j->p >= j->end || *j->p != '[')
        return -1;
    j->p++;
    for (long i = 0;; i++) {
        skip_ws(j);
        if (j->p >= j->end || *j->p == ']')
            return -1;
        if (i == idx)
            return 0;
        if (skip_value(j) < 0)
            return -1;
        skip_ws(j);
        if (j->p >= j->end)
            return -1;
        if (*j->p == ',') {
            j->p++;
            continue;
        }
        return -1;
    }
}

int json_extract(const char *doc, size_t len, const char *path, buf_t *out)
{
    js_t j = { doc, doc + len, 0 };
    const char *p = path;

    /* walk the path: segments separated by '.', with optional [n] indexes */
    while (*p) {
        if (*p == '.') {
            p++;
            continue;
        }
        if (*p == '[') {
            char *end;
            long idx = strtol(p + 1, &end, 10);
            if (end == p + 1 || *end != ']' || idx < 0)
                return JSON_NONE;
            if (descend_array(&j, idx) < 0)
                return JSON_NONE;
            p = end + 1;
            continue;
        }
        const char *s = p;
        while (*p && *p != '.' && *p != '[')
            p++;
        if (descend_object(&j, s, (size_t)(p - s)) < 0)
            return JSON_NONE;
    }

    skip_ws(&j);
    if (j.p >= j.end)
        return JSON_NONE;
    buf_reset(out);
    char c = *j.p;
    if (c == '"')
        return decode_string(&j, out) == 0 ? JSON_STRING : JSON_NONE;
    const char *start = j.p;
    if (c == '{' || c == '[') {
        if (skip_value(&j) < 0)
            return JSON_NONE;
        buf_append(out, start, (size_t)(j.p - start));
        return c == '{' ? JSON_OBJECT : JSON_ARRAY;
    }
    if (skip_value(&j) < 0)
        return JSON_NONE;
    size_t n = (size_t)(j.p - start);
    buf_append(out, start, n);
    if (n == 4 && memcmp(start, "true", 4) == 0)
        return JSON_BOOL;
    if (n == 5 && memcmp(start, "false", 5) == 0)
        return JSON_BOOL;
    if (n == 4 && memcmp(start, "null", 4) == 0)
        return JSON_NULL;
    return JSON_NUMBER;
}
