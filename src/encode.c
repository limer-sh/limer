/* encode.c - response compression (gzip via zlib, zstd, brotli) */
#include "limer.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef LIMER_ENCODE
#include <zlib.h>
#include <zstd.h>
#include <brotli/encode.h>
#endif

enum { ENC_NONE = 0, ENC_GZIP, ENC_ZSTD, ENC_BR };

struct encoder {
    int kind;
#ifdef LIMER_ENCODE
    z_stream z;
    ZSTD_CStream *zs;
    BrotliEncoderState *br;
#endif
};

const char *encode_name(const encoder_t *e)
{
    switch (e ? e->kind : 0) {
    case ENC_GZIP: return "gzip";
    case ENC_ZSTD: return "zstd";
    case ENC_BR: return "br";
    }
    return "identity";
}

static int kind_of(const char *name)
{
    if (strcasecmp(name, "gzip") == 0) return ENC_GZIP;
    if (strcasecmp(name, "zstd") == 0) return ENC_ZSTD;
    if (strcasecmp(name, "br") == 0) return ENC_BR;
    return ENC_NONE;
}

/* Does an Accept-Encoding header accept `name` (and not with q=0)? */
static int accepts(const char *ae, const char *name)
{
    size_t nl = strlen(name);
    const char *p = ae;
    while (*p) {
        while (*p == ' ' || *p == ',' || *p == '\t')
            p++;
        const char *start = p;
        while (*p && *p != ',')
            p++;
        const char *end = p;
        const char *semi = memchr(start, ';', (size_t)(end - start));
        const char *tend = semi ? semi : end;
        while (tend > start && (tend[-1] == ' ' || tend[-1] == '\t'))
            tend--;
        int match = (size_t)(tend - start) == nl && strncasecmp(start, name, nl) == 0;
        int star = (tend - start) == 1 && *start == '*';
        if (match || star) {
            if (semi) {
                const char *q = strstr(semi, "q=");
                if (q && q < end && atof(q + 2) <= 0.0)
                    return 0;
            }
            return 1;
        }
    }
    return 0;
}

const char *encode_choose(const char *server_list, const char *accept_encoding)
{
    if (!server_list || !accept_encoding)
        return NULL;
    static const char *names[] = { "zstd", "br", "gzip" };
    /* server order wins */
    const char *p = server_list;
    while (*p) {
        while (*p == ' ')
            p++;
        const char *s = p;
        while (*p && *p != ' ')
            p++;
        for (int i = 0; i < 3; i++) {
            if ((size_t)(p - s) == strlen(names[i]) && strncasecmp(s, names[i], (size_t)(p - s)) == 0 &&
                accepts(accept_encoding, names[i]))
                return names[i];
        }
    }
    return NULL;
}

int encode_compressible(const char *content_type)
{
    if (!content_type)
        return 0;
    /* An event stream stays open for as long as the page does: compressing it would hold an encoder
     * for the life of every stream and delay each event behind the encoder's buffering. It goes as is. */
    if (strncasecmp(content_type, "text/event-stream", 17) == 0)
        return 0;
    static const char *prefixes[] = {
        "text/", "application/json", "application/javascript", "application/x-javascript",
        "application/ecmascript", "application/xml", "application/xhtml+xml", "application/rss+xml",
        "application/atom+xml", "image/svg+xml", "application/wasm", "application/ld+json",
        "application/manifest+json", "application/x-www-form-urlencoded", "font/ttf", "font/otf",
        "application/vnd.api+json", "application/graphql", "application/x-ndjson", NULL
    };
    for (int i = 0; prefixes[i]; i++)
        if (strncasecmp(content_type, prefixes[i], strlen(prefixes[i])) == 0)
            return 1;
    return 0;
}

#ifdef LIMER_ENCODE

encoder_t *encoder_new(const char *name)
{
    int kind = kind_of(name);
    if (kind == ENC_NONE)
        return NULL;
    encoder_t *e = xcalloc(1, sizeof *e);
    e->kind = kind;
    if (kind == ENC_GZIP) {
        if (deflateInit2(&e->z, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
            free(e);
            return NULL;
        }
    } else if (kind == ENC_ZSTD) {
        e->zs = ZSTD_createCStream();
        if (!e->zs) {
            free(e);
            return NULL;
        }
        ZSTD_CCtx_setParameter(e->zs, ZSTD_c_compressionLevel, 3);
    } else {
        e->br = BrotliEncoderCreateInstance(NULL, NULL, NULL);
        if (!e->br) {
            free(e);
            return NULL;
        }
        BrotliEncoderSetParameter(e->br, BROTLI_PARAM_QUALITY, 5);
    }
    return e;
}

int encoder_write(encoder_t *e, const void *in, size_t n, buf_t *out, int flush)
{
    if (e->kind == ENC_GZIP) {
        e->z.next_in = (Bytef *)in;
        e->z.avail_in = (uInt)n;
        int mode = flush == 2 ? Z_FINISH : flush == 1 ? Z_SYNC_FLUSH : Z_NO_FLUSH;
        do {
            if (buf_reserve(out, 16384) < 0)
                return -1;
            e->z.next_out = (Bytef *)buf_wptr(out);
            e->z.avail_out = (uInt)buf_wavail(out);
            int rc = deflate(&e->z, mode);
            if (rc == Z_STREAM_ERROR)
                return -1;
            buf_commit(out, buf_wavail(out) - e->z.avail_out);
            if (rc == Z_STREAM_END)
                break;
        } while (e->z.avail_out == 0 || e->z.avail_in > 0);
        return 0;
    }
    if (e->kind == ENC_ZSTD) {
        ZSTD_inBuffer ib = { in, n, 0 };
        ZSTD_EndDirective mode = flush == 2 ? ZSTD_e_end : flush == 1 ? ZSTD_e_flush : ZSTD_e_continue;
        for (;;) {
            if (buf_reserve(out, 16384) < 0)
                return -1;
            ZSTD_outBuffer ob = { buf_wptr(out), buf_wavail(out), 0 };
            size_t rem = ZSTD_compressStream2(e->zs, &ob, &ib, mode);
            if (ZSTD_isError(rem))
                return -1;
            buf_commit(out, ob.pos);
            if (ib.pos < ib.size)
                continue;
            if (mode == ZSTD_e_continue || rem == 0)
                break;
        }
        return 0;
    }
    /* brotli */
    const uint8_t *next_in = in;
    size_t avail_in = n;
    BrotliEncoderOperation op = flush == 2 ? BROTLI_OPERATION_FINISH : flush == 1 ? BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_PROCESS;
    for (;;) {
        if (buf_reserve(out, 16384) < 0)
            return -1;
        size_t avail_out = buf_wavail(out);
        uint8_t *next_out = (uint8_t *)buf_wptr(out);
        if (!BrotliEncoderCompressStream(e->br, op, &avail_in, &next_in, &avail_out, &next_out, NULL))
            return -1;
        buf_commit(out, buf_wavail(out) - avail_out);
        if (avail_in == 0 && !BrotliEncoderHasMoreOutput(e->br) && (op == BROTLI_OPERATION_PROCESS || BrotliEncoderIsFinished(e->br) || op == BROTLI_OPERATION_FLUSH))
            break;
    }
    return 0;
}

void encoder_free(encoder_t *e)
{
    if (!e)
        return;
    if (e->kind == ENC_GZIP)
        deflateEnd(&e->z);
    else if (e->kind == ENC_ZSTD)
        ZSTD_freeCStream(e->zs);
    else if (e->br)
        BrotliEncoderDestroyInstance(e->br);
    free(e);
}

int encode_available(void) { return 1; }

#else

encoder_t *encoder_new(const char *name) { (void)name; return NULL; }
int encoder_write(encoder_t *e, const void *in, size_t n, buf_t *out, int flush) { (void)e; (void)in; (void)n; (void)out; (void)flush; return -1; }
void encoder_free(encoder_t *e) { (void)e; }
int encode_available(void) { return 0; }

#endif
