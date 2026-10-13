/* tls.c - optional TLS termination via OpenSSL */
#include "limer.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef LIMER_TLS
#include <openssl/err.h>

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg)
{
    static const unsigned char http11[] = "\x08http/1.1";
    (void)ssl; (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen, http11, sizeof http11 - 1, in, inlen) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_NOACK;
}

static const char *tls_last_error(void)
{
    static char buf[256];
    unsigned long e = ERR_peek_last_error();
    if (!e)
        return strerror(errno);
    const char *r = ERR_reason_error_string(e);
    if (r && (ERR_GET_REASON(e) == ERR_R_SYS_LIB))
        snprintf(buf, sizeof buf, "%s", strerror(errno));
    else
        ERR_error_string_n(e, buf, sizeof buf);
    ERR_clear_error();
    return buf;
}

int tls_init_server(server_t *s, char *err, size_t errlen)
{
    static int lib_init;
    if (!lib_init) {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
        lib_init = 1;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        snprintf(err, errlen, "tls: SSL_CTX_new failed");
        return -1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    if (SSL_CTX_use_certificate_chain_file(ctx, s->tls_cert) != 1) {
        snprintf(err, errlen, "tls: cannot load certificate '%s': %s", s->tls_cert, tls_last_error());
        SSL_CTX_free(ctx);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, s->tls_key, SSL_FILETYPE_PEM) != 1) {
        snprintf(err, errlen, "tls: cannot load private key '%s': %s", s->tls_key, tls_last_error());
        SSL_CTX_free(ctx);
        return -1;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        snprintf(err, errlen, "tls: certificate and key do not match");
        SSL_CTX_free(ctx);
        return -1;
    }
    s->ssl_ctx = ctx;
    return 0;
}

void tls_free_server(server_t *s)
{
    if (s->ssl_ctx) {
        SSL_CTX_free(s->ssl_ctx);
        s->ssl_ctx = NULL;
    }
}

#else

int tls_init_server(server_t *s, char *err, size_t errlen)
{
    (void)s;
    snprintf(err, errlen, "tls: this build has no TLS support (rebuild with OpenSSL available)");
    return -1;
}

void tls_free_server(server_t *s)
{
    (void)s;
}

#endif
