/* tls.c - TLS termination via OpenSSL: certificate files, self-signed
 * "internal" certificates, and SNI-based context selection. */
#include "limer.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef LIMER_TLS
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

static int lib_init;

static void tls_lib_init(void)
{
    if (!lib_init) {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
        lib_init = 1;
    }
}

static const char *tls_last_error(void)
{
    static char buf[256];
    unsigned long e = ERR_peek_last_error();
    if (!e)
        return strerror(errno);
    if (ERR_GET_REASON(e) == ERR_R_SYS_LIB)
        snprintf(buf, sizeof buf, "%s", strerror(errno));
    else
        ERR_error_string_n(e, buf, sizeof buf);
    ERR_clear_error();
    return buf;
}

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg)
{
#ifdef LIMER_H2
    static const unsigned char protos[] = "\x02h2\x08http/1.1";
#else
    static const unsigned char protos[] = "\x08http/1.1";
#endif
    (void)ssl; (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen, protos, sizeof protos - 1, in, inlen) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_NOACK;
}

/* The proxy registers a resolver that maps (connection, SNI name) to the
 * right server's context; see tls_set_sni_resolver(). */
static SSL_CTX *(*sni_resolver)(SSL *ssl, const char *name);

void tls_set_sni_resolver(SSL_CTX *(*fn)(SSL *, const char *))
{
    sni_resolver = fn;
}

static int servername_cb(SSL *ssl, int *al, void *arg)
{
    (void)al; (void)arg;
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (name && sni_resolver) {
        SSL_CTX *ctx = sni_resolver(ssl, name);
        if (ctx && ctx != SSL_get_SSL_CTX(ssl))
            SSL_set_SSL_CTX(ssl, ctx);
    }
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *new_ctx(char *err, size_t errlen)
{
    tls_lib_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        snprintf(err, errlen, "tls: SSL_CTX_new failed");
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    SSL_CTX_set_tlsext_servername_callback(ctx, servername_cb);
    return ctx;
}

int tls_load_pem(server_t *s, const char *cert, const char *key, char *err, size_t errlen)
{
    SSL_CTX *ctx = new_ctx(err, errlen);
    if (!ctx)
        return -1;
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) {
        snprintf(err, errlen, "tls: cannot load certificate '%s': %s", cert, tls_last_error());
        SSL_CTX_free(ctx);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        snprintf(err, errlen, "tls: cannot load private key '%s': %s", key, tls_last_error());
        SSL_CTX_free(ctx);
        return -1;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        snprintf(err, errlen, "tls: certificate and key do not match");
        SSL_CTX_free(ctx);
        return -1;
    }
    if (s->ssl_ctx)
        SSL_CTX_free(s->ssl_ctx);
    s->ssl_ctx = ctx;
    return 0;
}

int tls_init_server(server_t *s, char *err, size_t errlen)
{
    return tls_load_pem(s, s->tls_cert, s->tls_key, err, errlen);
}

/* Generate a self-signed ECDSA P-256 certificate covering the site's hosts. */
int tls_init_internal(server_t *s, char *err, size_t errlen)
{
    SSL_CTX *ctx = new_ctx(err, errlen);
    if (!ctx)
        return -1;
    EVP_PKEY *pkey = EVP_EC_gen("P-256");
    X509 *x = X509_new();
    int ok = 0;
    if (!pkey || !x) {
        snprintf(err, errlen, "tls internal: key generation failed");
        goto out;
    }
    ASN1_INTEGER_set(X509_get_serialNumber(x), (long)(now_wall()));
    X509_set_version(x, 2);
    X509_gmtime_adj(X509_get_notBefore(x), -3600);
    X509_gmtime_adj(X509_get_notAfter(x), 365L * 24 * 3600);
    X509_set_pubkey(x, pkey);
    X509_NAME *name = X509_get_subject_name(x);
    const char *cn = s->nhosts ? s->hosts[0] : "localhost";
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *)"Limer Local", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(x, name);
    /* subjectAltName from the hosts (DNS or IP); wildcards are kept as-is */
    buf_t san;
    buf_init(&san);
    if (s->nhosts == 0)
        buf_puts(&san, "DNS:localhost,IP:127.0.0.1,IP:::1");
    for (int i = 0; i < s->nhosts; i++) {
        if (i)
            buf_puts(&san, ",");
        buf_printf(&san, "%s:%s", is_ip_literal(s->hosts[i]) ? "IP" : "DNS", s->hosts[i]);
    }
    buf_append(&san, "", 1);
    X509V3_CTX v3;
    X509V3_set_ctx_nodb(&v3);
    X509V3_set_ctx(&v3, x, x, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &v3, NID_subject_alt_name, san.data);
    if (ext) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    ext = X509V3_EXT_conf_nid(NULL, &v3, NID_basic_constraints, "CA:FALSE");
    if (ext) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    buf_free(&san);
    if (X509_sign(x, pkey, EVP_sha256()) <= 0) {
        snprintf(err, errlen, "tls internal: signing failed: %s", tls_last_error());
        goto out;
    }
    if (SSL_CTX_use_certificate(ctx, x) != 1 || SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        snprintf(err, errlen, "tls internal: cannot install certificate: %s", tls_last_error());
        goto out;
    }
    ok = 1;
out:
    if (x)
        X509_free(x);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (!ok) {
        SSL_CTX_free(ctx);
        return -1;
    }
    if (s->ssl_ctx)
        SSL_CTX_free(s->ssl_ctx);
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

int tls_init_pool_client(pool_t *p, char *err, size_t errlen)
{
    tls_lib_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        snprintf(err, errlen, "tls: SSL_CTX_new failed");
        return -1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (p->tls_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (p->tls_ca) {
            if (SSL_CTX_load_verify_locations(ctx, p->tls_ca, NULL) != 1) {
                snprintf(err, errlen, "tls: cannot load tls_trusted_ca_certs '%s': %s", p->tls_ca, tls_last_error());
                SSL_CTX_free(ctx);
                return -1;
            }
        } else {
            SSL_CTX_set_default_verify_paths(ctx);
        }
    }
    if (p->client_ctx)
        SSL_CTX_free(p->client_ctx);
    p->client_ctx = ctx;
    return 0;
}

void tls_free_pool_client(pool_t *p)
{
    if (p->client_ctx) {
        SSL_CTX_free(p->client_ctx);
        p->client_ctx = NULL;
    }
}

#else

int tls_init_server(server_t *s, char *err, size_t errlen)
{
    (void)s;
    snprintf(err, errlen, "tls: this build has no TLS support (rebuild with OpenSSL available)");
    return -1;
}

int tls_init_internal(server_t *s, char *err, size_t errlen)
{
    return tls_init_server(s, err, errlen);
}

int tls_load_pem(server_t *s, const char *cert, const char *key, char *err, size_t errlen)
{
    (void)cert; (void)key;
    return tls_init_server(s, err, errlen);
}

void tls_free_server(server_t *s)
{
    (void)s;
}

int tls_init_pool_client(pool_t *p, char *err, size_t errlen)
{
    (void)p;
    snprintf(err, errlen, "tls: this build has no TLS support (https upstreams unavailable)");
    return -1;
}

void tls_free_pool_client(pool_t *p)
{
    (void)p;
}

#endif
