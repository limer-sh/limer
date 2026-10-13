/* buf.c - growable byte buffer */
#include "limer.h"
#include <stdlib.h>
#include <string.h>

void buf_init(buf_t *b)
{
    b->data = NULL;
    b->off = b->len = b->cap = 0;
}

void buf_free(buf_t *b)
{
    free(b->data);
    buf_init(b);
}

void buf_reset(buf_t *b)
{
    b->off = b->len = 0;
}

int buf_reserve(buf_t *b, size_t extra)
{
    if (b->cap - b->len >= extra)
        return 0;
    /* try compacting first */
    if (b->off > 0) {
        buf_compact(b);
        if (b->cap - b->len >= extra)
            return 0;
    }
    size_t ncap = b->cap ? b->cap : 1024;
    while (ncap - b->len < extra) {
        if (ncap > (SIZE_MAX / 2))
            return -1;
        ncap *= 2;
    }
    char *nd = realloc(b->data, ncap);
    if (!nd)
        return -1;
    b->data = nd;
    b->cap = ncap;
    return 0;
}

int buf_append(buf_t *b, const void *p, size_t n)
{
    if (n == 0)
        return 0;
    if (buf_reserve(b, n) < 0)
        return -1;
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

int buf_puts(buf_t *b, const char *s)
{
    return buf_append(b, s, strlen(s));
}

int buf_printf(buf_t *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        return -1;
    }
    if (buf_reserve(b, (size_t)n + 1) < 0) {
        va_end(ap2);
        return -1;
    }
    vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
    return 0;
}

void buf_consume(buf_t *b, size_t n)
{
    if (n > b->len - b->off)
        n = b->len - b->off;
    b->off += n;
    if (b->off == b->len)
        b->off = b->len = 0;
}

void buf_compact(buf_t *b)
{
    if (b->off == 0)
        return;
    size_t rem = b->len - b->off;
    if (rem)
        memmove(b->data, b->data + b->off, rem);
    b->len = rem;
    b->off = 0;
}
