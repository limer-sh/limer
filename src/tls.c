/* tls.c - TLS termination via OpenSSL: certificate files, self-signed
 * "internal" certificates, and SNI-based context selection. */
#include "limer.h"
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef LIMER_TLS
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

static int lib_init;
static int acme_ex_index = -1;   /* SSL ex_data slot: non-NULL = answer acme-tls/1 */

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
    static const unsigned char acme_proto[] = "\x0a" "acme-tls/1";
    (void)arg;
    if (acme_ex_index >= 0 && SSL_get_ex_data(ssl, acme_ex_index)) {
        if (SSL_select_next_proto((unsigned char **)out, outlen, acme_proto, sizeof acme_proto - 1, in, inlen) == OPENSSL_NPN_NEGOTIATED)
            return SSL_TLSEXT_ERR_OK;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    if (SSL_select_next_proto((unsigned char **)out, outlen, protos, sizeof protos - 1, in, inlen) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_NOACK;
}

/* The proxy registers a resolver that maps (connection, SNI name) to the
 * right server's context; see tls_set_sni_resolver(). */
static SSL_CTX *(*sni_resolver)(SSL *ssl, const char *name);
static int (*acme_resolver)(SSL *ssl, const char *name, char *keyauth, size_t n);

void tls_set_sni_resolver(SSL_CTX *(*fn)(SSL *, const char *))
{
    sni_resolver = fn;
}

void tls_set_acme_resolver(int (*fn)(SSL *, const char *, char *, size_t))
{
    acme_resolver = fn;
}

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg);

/* ---- tls-alpn-01 validation certificates (RFC 8737) ---- */

#define ACME_CTX_CACHE 8
static struct {
    char name[256];
    char keyauth[512];
    SSL_CTX *ctx;
} acme_cache[ACME_CTX_CACHE];
static int acme_cache_next;

static SSL_CTX *acme_validation_ctx(const char *name, const char *keyauth)
{
    for (int i = 0; i < ACME_CTX_CACHE; i++)
        if (acme_cache[i].ctx && strcmp(acme_cache[i].name, name) == 0 && strcmp(acme_cache[i].keyauth, keyauth) == 0)
            return acme_cache[i].ctx;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    EVP_PKEY *pkey = EVP_EC_gen("P-256");
    X509 *x = X509_new();
    int ok = 0;
    if (pkey && x) {
        ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
        X509_set_version(x, 2);
        X509_gmtime_adj(X509_get_notBefore(x), -60);
        X509_gmtime_adj(X509_get_notAfter(x), 3600);
        X509_set_pubkey(x, pkey);
        X509_NAME *nm = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)name, -1, -1, 0);
        X509_set_issuer_name(x, nm);
        char san[300];
        snprintf(san, sizeof san, "DNS:%s", name);
        X509V3_CTX v3;
        X509V3_set_ctx_nodb(&v3);
        X509V3_set_ctx(&v3, x, x, NULL, NULL, 0);
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &v3, NID_subject_alt_name, san);
        if (ext) {
            X509_add_ext(x, ext, -1);
            X509_EXTENSION_free(ext);
        }
        /* id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31): OCTET STRING of SHA-256(keyauth), critical */
        unsigned char dg[32];
        unsigned int dl = 0;
        EVP_Digest(keyauth, strlen(keyauth), dg, &dl, EVP_sha256(), NULL);
        ASN1_OCTET_STRING *inner = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(inner, dg, 32);
        unsigned char *der = NULL;
        int dlen = i2d_ASN1_OCTET_STRING(inner, &der);
        ASN1_OCTET_STRING_free(inner);
        ASN1_OBJECT *obj = OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1);
        if (dlen > 0 && obj) {
            ASN1_OCTET_STRING *val = ASN1_OCTET_STRING_new();
            ASN1_OCTET_STRING_set(val, der, dlen);
            X509_EXTENSION *aext = X509_EXTENSION_create_by_OBJ(NULL, obj, 1, val);
            if (aext) {
                X509_add_ext(x, aext, -1);
                X509_EXTENSION_free(aext);
                ok = 1;
            }
            ASN1_OCTET_STRING_free(val);
        }
        OPENSSL_free(der);
        ASN1_OBJECT_free(obj);
        if (ok && X509_sign(x, pkey, EVP_sha256()) <= 0)
            ok = 0;
        if (ok && (SSL_CTX_use_certificate(ctx, x) != 1 || SSL_CTX_use_PrivateKey(ctx, pkey) != 1))
            ok = 0;
    }
    if (x)
        X509_free(x);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (!ok) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    int slot = acme_cache_next++ % ACME_CTX_CACHE;
    if (acme_cache[slot].ctx)
        SSL_CTX_free(acme_cache[slot].ctx);
    snprintf(acme_cache[slot].name, sizeof acme_cache[slot].name, "%s", name);
    snprintf(acme_cache[slot].keyauth, sizeof acme_cache[slot].keyauth, "%s", keyauth);
    acme_cache[slot].ctx = ctx;
    return ctx;
}

/* Runs on every ClientHello: detect acme-tls/1 and switch to a validation certificate. */
static int client_hello_cb(SSL *ssl, int *al, void *arg)
{
    (void)al; (void)arg;
    if (!acme_resolver)
        return SSL_CLIENT_HELLO_SUCCESS;
    const unsigned char *ext = NULL;
    size_t extlen = 0;
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &ext, &extlen) || extlen < 2)
        return SSL_CLIENT_HELLO_SUCCESS;
    /* ALPN ext: u16 list length, then (u8 len, bytes)* */
    size_t pos = 2;
    int acme = 0;
    while (pos < extlen) {
        size_t l = ext[pos++];
        if (pos + l > extlen)
            break;
        if (l == 10 && memcmp(ext + pos, "acme-tls/1", 10) == 0)
            acme = 1;
        pos += l;
    }
    if (!acme)
        return SSL_CLIENT_HELLO_SUCCESS;
    const unsigned char *sni = NULL;
    size_t snilen = 0;
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &sni, &snilen) || snilen < 5)
        return SSL_CLIENT_HELLO_SUCCESS;
    /* server_name ext: u16 list len, u8 type(0), u16 name len, name */
    size_t nlen = ((size_t)sni[3] << 8) | sni[4];
    if (5 + nlen > snilen || nlen >= 256)
        return SSL_CLIENT_HELLO_SUCCESS;
    char name[256];
    memcpy(name, sni + 5, nlen);
    name[nlen] = 0;
    for (char *q = name; *q; q++)
        *q = (char)tolower((unsigned char)*q);
    char keyauth[512];
    if (!acme_resolver(ssl, name, keyauth, sizeof keyauth))
        return SSL_CLIENT_HELLO_SUCCESS;
    SSL_CTX *vctx = acme_validation_ctx(name, keyauth);
    if (!vctx)
        return SSL_CLIENT_HELLO_SUCCESS;
    SSL_set_SSL_CTX(ssl, vctx);
    SSL_set_ex_data(ssl, acme_ex_index, (void *)1);
    return SSL_CLIENT_HELLO_SUCCESS;
}

static int servername_cb(SSL *ssl, int *al, void *arg)
{
    (void)al; (void)arg;
    if (acme_ex_index >= 0 && SSL_get_ex_data(ssl, acme_ex_index))
        return SSL_TLSEXT_ERR_OK; /* tls-alpn-01 validation keeps its certificate */
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
    SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, NULL);
    if (acme_ex_index < 0)
        acme_ex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
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
