/*
 * acme.c - automatic HTTPS: certificate storage, http-01 challenge serving,
 * and a certificate manager process that obtains and renews certificates
 * from an ACME CA (RFC 8555) such as Let's Encrypt.
 *
 * The manager is a forked child of the main process. It talks to the CA
 * over a small blocking HTTPS client built on OpenSSL, writes challenge key
 * authorisations into <storage>/challenges/<token> (served by the plain
 * http listener), stores the issued certificate under
 * <storage>/certs/<host>/, and sends SIGHUP to its parent so the new
 * certificate is loaded.
 */
#include "limer.h"
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef LIMER_TLS
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#endif

#define ACME_RENEW_BEFORE   (30.0 * 86400)   /* renew when less than this remains */
#define ACME_CHECK_INTERVAL 3600             /* seconds between renewal checks   */
#define ACME_MAX_BODY       (1 << 20)

/* ------------------------------------------------------------------ */
/* Storage helpers                                                     */
/* ------------------------------------------------------------------ */

static int file_exists(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static int write_file_atomic(const char *path, const void *data, size_t n, mode_t mode)
{
    char tmp[2048];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    const char *p = data;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) {
            close(fd);
            unlink(tmp);
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    fsync(fd);
    close(fd);
    if (rename(tmp, path) < 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static char *read_small_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    buf_t b;
    buf_init(&b);
    char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0)
        buf_append(&b, tmp, n);
    fclose(f);
    buf_append(&b, "", 1);
    if (len)
        *len = b.len - 1;
    char *out = xstrdup(b.data);
    buf_free(&b);
    return out;
}

/* Load <storage>/certs/<first host>/{cert,key}.pem into the server if present. */
int acme_load_stored(config_t *cfg, server_t *s, char *err, size_t errlen)
{
    (void)err; (void)errlen;
    if (s->nhosts == 0)
        return 0;
    char cert[2048], key[2048];
    snprintf(cert, sizeof cert, "%s/certs/%s/cert.pem", cfg->storage, s->hosts[0]);
    snprintf(key, sizeof key, "%s/certs/%s/key.pem", cfg->storage, s->hosts[0]);
    if (!file_exists(cert) || !file_exists(key))
        return 0; /* not obtained yet: keep the temporary certificate */
    char lerr[256];
    if (tls_load_pem(s, cert, key, lerr, sizeof lerr) < 0) {
        LOGW("site %s: stored certificate unusable (%s); using a temporary one", s->hosts[0], lerr);
        return 0;
    }
    LOGI("site %s: loaded certificate from %s", s->hosts[0], cert);
    return 0;
}

/* http-01 key authorisation lookup: <storage>/challenges/<token> */
int acme_challenge_lookup(const config_t *cfg, const char *token, buf_t *out)
{
    for (const char *p = token; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))
            return 0;
    if (!*token || strlen(token) > 128)
        return 0;
    char path[2048];
    snprintf(path, sizeof path, "%s/challenges/%s", cfg->storage, token);
    size_t n;
    char *data = read_small_file(path, &n);
    if (!data)
        return 0;
    buf_reset(out);
    buf_append(out, data, n);
    free(data);
    return 1;
}

#ifdef LIMER_TLS

/* ------------------------------------------------------------------ */
/* Minimal blocking HTTPS client                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    int status;
    hdr_t hdrs[HTTP_MAX_HEADERS];
    int nhdr;
    char *raw;
    buf_t body;
} aresp_t;

static void aresp_free(aresp_t *r)
{
    free(r->raw);
    buf_free(&r->body);
    memset(r, 0, sizeof *r);
}

static const char *aresp_hdr(const aresp_t *r, const char *name)
{
    return http_hdr_get(r->hdrs, r->nhdr, name);
}

typedef struct {
    const config_t *cfg;
    SSL_CTX *ctx;
    char nonce[256];
    char dir_new_nonce[1024], dir_new_account[1024], dir_new_order[1024];
    EVP_PKEY *account_key;
    char kid[1024];
    char thumbprint[128];
} acme_t;

static int url_split(const char *url, char *host, size_t hl, int *port, char *path, size_t pl, int *tls)
{
    const char *p = url;
    if (str_has_prefix(p, "https://")) {
        *tls = 1;
        p += 8;
        *port = 443;
    } else if (str_has_prefix(p, "http://")) {
        *tls = 0;
        p += 7;
        *port = 80;
    } else {
        return -1;
    }
    const char *slash = strchr(p, '/');
    size_t hostlen = slash ? (size_t)(slash - p) : strlen(p);
    char hp[256];
    if (hostlen >= sizeof hp || hl < sizeof hp)
        return -1;
    memcpy(hp, p, hostlen);
    hp[hostlen] = 0;
    char *colon = strrchr(hp, ':');
    if (colon && !strchr(colon, ']')) {
        *colon = 0;
        *port = atoi(colon + 1);
    }
    snprintf(host, hl, "%s", hp[0] == '[' ? hp + 1 : hp);
    size_t n = strlen(host);
    if (n && host[n - 1] == ']')
        host[n - 1] = 0;
    snprintf(path, pl, "%s", slash ? slash : "/");
    return 0;
}

static int tcp_connect_blocking(const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    char ps[16];
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(host, ps, &hints, &res) != 0)
        return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
            continue;
        struct timeval tv = { 20, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Perform one request; returns 0 on success (any status), -1 on transport error. */
static int https_call(acme_t *a, const char *method, const char *url, const char *body, const char *ctype, aresp_t *out)
{
    memset(out, 0, sizeof *out);
    buf_init(&out->body);
    char host[300], path[2048];
    int port, tls;
    if (url_split(url, host, sizeof host, &port, path, sizeof path, &tls) < 0) {
        LOGE("acme: bad url %s", url);
        return -1;
    }
    LOGD("acme: %s %s (host %s port %d path %s)", method, url, host, port, path);
    int fd = tcp_connect_blocking(host, port);
    if (fd < 0) {
        LOGE("acme: cannot connect to %s:%d: %s", host, port, strerror(errno));
        return -1;
    }
    SSL *ssl = NULL;
    if (tls) {
        ssl = SSL_new(a->ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, host);
        SSL_set1_host(ssl, host);
        if (SSL_connect(ssl) != 1) {
            LOGE("acme: TLS handshake with %s failed: %s", host, ERR_reason_error_string(ERR_peek_last_error()));
            SSL_free(ssl);
            close(fd);
            return -1;
        }
    }
    buf_t req;
    buf_init(&req);
    int default_port = tls ? 443 : 80;
    if (port == default_port)
        buf_printf(&req, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, host);
    else
        buf_printf(&req, "%s %s HTTP/1.1\r\nHost: %s:%d\r\n", method, path, host, port);
    buf_printf(&req, "User-Agent: limer/%s\r\nAccept: */*\r\nConnection: close\r\n", LIMER_VERSION);
    if (body) {
        buf_printf(&req, "Content-Type: %s\r\nContent-Length: %zu\r\n", ctype, strlen(body));
    }
    buf_puts(&req, "\r\n");
    if (body)
        buf_puts(&req, body);
    size_t off = 0;
    int rc = 0;
    while (off < req.len) {
        int w = tls ? SSL_write(ssl, req.data + off, (int)(req.len - off)) : (int)write(fd, req.data + off, req.len - off);
        if (w <= 0) {
            rc = -1;
            break;
        }
        off += (size_t)w;
    }
    buf_free(&req);
    buf_t in;
    buf_init(&in);
    http_resp_t resp;
    http_resp_init(&resp);
    int head_done = 0;
    size_t consumed = 0;
    chunk_state_t cs;
    memset(&cs, 0, sizeof cs);
    int64_t remaining = -1;
    while (rc == 0) {
        if (buf_reserve(&in, 16384) < 0) {
            rc = -1;
            break;
        }
        int r = tls ? SSL_read(ssl, buf_wptr(&in), (int)buf_wavail(&in)) : (int)read(fd, buf_wptr(&in), buf_wavail(&in));
        if (r <= 0) {
            if (!head_done)
                rc = -1;
            break;
        }
        buf_commit(&in, (size_t)r);
        if (!head_done) {
            int pr = http_parse_response_head(&resp, buf_rptr(&in), buf_readable(&in), &consumed);
            if (pr == 0)
                continue;
            if (pr < 0) {
                rc = -1;
                break;
            }
            buf_consume(&in, consumed);
            head_done = 1;
            if (resp.content_length >= 0)
                remaining = resp.content_length;
        }
        if (head_done) {
            if (resp.chunked) {
                size_t c2 = 0;
                if (http_chunk_scan(&cs, buf_rptr(&in), buf_readable(&in), &c2, &out->body) < 0) {
                    rc = -1;
                    break;
                }
                buf_consume(&in, c2);
                if (cs.done)
                    break;
            } else if (remaining >= 0) {
                size_t take = buf_readable(&in);
                if ((int64_t)take > remaining)
                    take = (size_t)remaining;
                buf_append(&out->body, buf_rptr(&in), take);
                buf_consume(&in, take);
                remaining -= (int64_t)take;
                if (remaining == 0)
                    break;
            } else {
                buf_append(&out->body, buf_rptr(&in), buf_readable(&in));
                buf_reset(&in);
            }
            if (buf_readable(&out->body) > ACME_MAX_BODY) {
                rc = -1;
                break;
            }
        }
    }
    buf_free(&in);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(fd);
    if (rc < 0 || !head_done) {
        http_resp_free(&resp);
        buf_free(&out->body);
        LOGE("acme: no valid response from %s", url);
        return -1;
    }
    LOGD("acme: response %d (%zu body bytes)", resp.status, buf_readable(&out->body));
    out->status = resp.status;
    out->raw = resp.raw; /* headers point into raw */
    memcpy(out->hdrs, resp.hdrs, sizeof out->hdrs);
    out->nhdr = resp.nhdr;
    buf_append(&out->body, "", 1);
    out->body.len--; /* keep NUL terminator beyond len */
    const char *nonce = aresp_hdr(out, "Replay-Nonce");
    if (nonce)
        snprintf(a->nonce, sizeof a->nonce, "%s", nonce);
    return 0;
}

/* ------------------------------------------------------------------ */
/* JOSE / JWS                                                          */
/* ------------------------------------------------------------------ */

static void b64url(const unsigned char *in, size_t n, buf_t *out)
{
    char *tmp = xmalloc(4 * (n / 3 + 2) + 1);
    size_t l = base64_encode(in, n, tmp, 1);
    buf_append(out, tmp, l);
    free(tmp);
}

static int jwk_json(EVP_PKEY *key, buf_t *out)
{
    unsigned char pub[80];
    size_t publen = 0;
    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof pub, &publen) || publen != 65)
        return -1;
    /* canonical member order for thumbprints: crv, kty, x, y */
    buf_puts(out, "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"");
    b64url(pub + 1, 32, out);
    buf_puts(out, "\",\"y\":\"");
    b64url(pub + 33, 32, out);
    buf_puts(out, "\"}");
    return 0;
}

static int jwk_thumbprint(EVP_PKEY *key, char *out, size_t outlen)
{
    buf_t j;
    buf_init(&j);
    if (jwk_json(key, &j) < 0) {
        buf_free(&j);
        return -1;
    }
    unsigned char dg[32];
    unsigned int dl = 0;
    EVP_Digest(j.data, j.len, dg, &dl, EVP_sha256(), NULL);
    buf_free(&j);
    char tmp[64];
    base64_encode(dg, 32, tmp, 1);
    snprintf(out, outlen, "%s", tmp);
    return 0;
}

/* ES256 signature of data, raw r||s, base64url appended to out */
static int es256_sign(EVP_PKEY *key, const char *data, size_t n, buf_t *out)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char der[128];
    size_t derlen = sizeof der;
    int ok = EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key) == 1 &&
             EVP_DigestSign(md, der, &derlen, (const unsigned char *)data, n) == 1;
    EVP_MD_CTX_free(md);
    if (!ok)
        return -1;
    const unsigned char *p = der;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)derlen);
    if (!sig)
        return -1;
    unsigned char raw[64];
    BN_bn2binpad(ECDSA_SIG_get0_r(sig), raw, 32);
    BN_bn2binpad(ECDSA_SIG_get0_s(sig), raw + 32, 32);
    ECDSA_SIG_free(sig);
    b64url(raw, 64, out);
    return 0;
}

static int acme_get_nonce(acme_t *a)
{
    aresp_t r;
    if (https_call(a, "HEAD", a->dir_new_nonce, NULL, NULL, &r) < 0)
        return -1;
    aresp_free(&r);
    return a->nonce[0] ? 0 : -1;
}

/* Signed POST (payload NULL = POST-as-GET). Retries once on badNonce. */
static int acme_post(acme_t *a, const char *url, const char *payload, aresp_t *out)
{
    for (int attempt = 0; attempt < 6; attempt++) {
        if (!a->nonce[0] && acme_get_nonce(a) < 0) {
            LOGE("acme: cannot obtain a nonce from %s", a->dir_new_nonce);
            return -1;
        }
        buf_t prot, body, signing;
        buf_init(&prot);
        buf_init(&body);
        buf_init(&signing);
        buf_puts(&prot, "{\"alg\":\"ES256\",");
        if (a->kid[0])
            buf_printf(&prot, "\"kid\":\"%s\",", a->kid);
        else {
            buf_puts(&prot, "\"jwk\":");
            jwk_json(a->account_key, &prot);
            buf_puts(&prot, ",");
        }
        buf_printf(&prot, "\"nonce\":\"%s\",\"url\":\"%s\"}", a->nonce, url);
        a->nonce[0] = 0; /* single use */
        buf_t pb, plb;
        buf_init(&pb);
        buf_init(&plb);
        b64url((const unsigned char *)prot.data, prot.len, &pb);
        if (payload)
            b64url((const unsigned char *)payload, strlen(payload), &plb);
        buf_append(&signing, pb.data, pb.len);
        buf_puts(&signing, ".");
        if (plb.len)
            buf_append(&signing, plb.data, plb.len);
        buf_t sig;
        buf_init(&sig);
        int src = es256_sign(a->account_key, signing.data, signing.len, &sig);
        buf_printf(&body, "{\"protected\":\"%.*s\",\"payload\":\"%.*s\",\"signature\":\"%.*s\"}",
                   (int)pb.len, pb.data, (int)plb.len, plb.len ? plb.data : "", (int)sig.len, sig.data ? sig.data : "");
        buf_append(&body, "", 1);
        buf_free(&prot);
        buf_free(&signing);
        buf_free(&pb);
        buf_free(&plb);
        buf_free(&sig);
        if (src < 0) {
            buf_free(&body);
            LOGE("acme: signing failed");
            return -1;
        }
        int rc = https_call(a, "POST", url, body.data, "application/jose+json", out);
        buf_free(&body);
        if (rc < 0)
            return -1;
        if (out->status == 400 && strstr(out->body.data ? out->body.data : "", "badNonce")) {
            LOGD("acme: bad nonce, retrying");
            aresp_free(out);
            continue;
        }
        return 0;
    }
    LOGE("acme: giving up on %s after repeated bad nonces", url);
    return -1;
}

static void acme_log_problem(const char *what, const aresp_t *r)
{
    buf_t t, d;
    buf_init(&t);
    buf_init(&d);
    const char *body = r->body.data ? r->body.data : "";
    json_extract(body, strlen(body), "type", &t);
    json_extract(body, strlen(body), "detail", &d);
    buf_append(&t, "", 1);
    buf_append(&d, "", 1);
    LOGE("acme: %s failed: HTTP %d %s %s", what, r->status, t.data, d.data);
    buf_free(&t);
    buf_free(&d);
}

/* extract a JSON string field into a fixed buffer; returns 1 if found */
static int jstr(const char *body, const char *path, char *out, size_t n)
{
    buf_t b;
    buf_init(&b);
    int t = json_extract(body, strlen(body), path, &b);
    if (t == JSON_NONE) {
        buf_free(&b);
        return 0;
    }
    snprintf(out, n, "%.*s", (int)buf_readable(&b), buf_rptr(&b));
    buf_free(&b);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Account                                                             */
/* ------------------------------------------------------------------ */

static int acme_init(acme_t *a, const config_t *cfg)
{
    memset(a, 0, sizeof *a);
    a->cfg = cfg;
    a->ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(a->ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(a->ctx, SSL_VERIFY_PEER, NULL);
    if (cfg->acme_ca_root) {
        if (SSL_CTX_load_verify_locations(a->ctx, cfg->acme_ca_root, NULL) != 1) {
            LOGE("acme: cannot load acme_ca_root %s", cfg->acme_ca_root);
            return -1;
        }
    } else {
        SSL_CTX_set_default_verify_paths(a->ctx);
    }
    /* account key: <storage>/acme/account.key */
    char dir[1024], keypath[2048], kidpath[2048];
    snprintf(dir, sizeof dir, "%s/acme", cfg->storage);
    mkdir_p(dir);
    snprintf(keypath, sizeof keypath, "%s/account.key", dir);
    snprintf(kidpath, sizeof kidpath, "%s/account.url", dir);
    FILE *f = fopen(keypath, "r");
    if (f) {
        a->account_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        fclose(f);
    }
    if (!a->account_key) {
        a->account_key = EVP_EC_gen("P-256");
        if (!a->account_key)
            return -1;
        f = fopen(keypath, "w");
        if (f) {
            fchmod(fileno(f), 0600);
            PEM_write_PrivateKey(f, a->account_key, NULL, NULL, 0, NULL, NULL);
            fclose(f);
        }
    }
    jwk_thumbprint(a->account_key, a->thumbprint, sizeof a->thumbprint);
    size_t n;
    char *kid = read_small_file(kidpath, &n);
    if (kid) {
        /* the stored account belongs to the CA it was created with */
        char *nl = strchr(kid, '\n');
        if (nl)
            *nl = 0;
        char *sep = strchr(kid, ' ');
        if (sep && strcmp(sep + 1, cfg->acme_ca) == 0) {
            *sep = 0;
            snprintf(a->kid, sizeof a->kid, "%s", kid);
        }
        free(kid);
    }
    /* directory */
    aresp_t r;
    if (https_call(a, "GET", cfg->acme_ca, NULL, NULL, &r) < 0)
        return -1;
    if (r.status != 200 || !jstr(r.body.data, "newNonce", a->dir_new_nonce, sizeof a->dir_new_nonce) ||
        !jstr(r.body.data, "newAccount", a->dir_new_account, sizeof a->dir_new_account) ||
        !jstr(r.body.data, "newOrder", a->dir_new_order, sizeof a->dir_new_order)) {
        LOGE("acme: directory %s is not usable (HTTP %d)", cfg->acme_ca, r.status);
        aresp_free(&r);
        return -1;
    }
    LOGD("acme: directory: newNonce=%s newAccount=%s newOrder=%s", a->dir_new_nonce, a->dir_new_account, a->dir_new_order);
    aresp_free(&r);
    if (a->kid[0])
        return 0;
    /* register */
    buf_t payload;
    buf_init(&payload);
    const char *email = cfg->acme_email;
    buf_puts(&payload, "{\"termsOfServiceAgreed\":true");
    if (email && *email)
        buf_printf(&payload, ",\"contact\":[\"mailto:%s\"]", email);
    buf_puts(&payload, "}");
    buf_append(&payload, "", 1);
    int rc = acme_post(a, a->dir_new_account, payload.data, &r);
    buf_free(&payload);
    if (rc < 0)
        return -1;
    if (r.status != 200 && r.status != 201) {
        acme_log_problem("account registration", &r);
        aresp_free(&r);
        return -1;
    }
    const char *loc = aresp_hdr(&r, "Location");
    if (!loc) {
        aresp_free(&r);
        return -1;
    }
    snprintf(a->kid, sizeof a->kid, "%s", loc);
    char line[2200];
    snprintf(line, sizeof line, "%s %s\n", loc, cfg->acme_ca);
    write_file_atomic(kidpath, line, strlen(line), 0600);
    LOGI("acme: registered account %s", loc);
    aresp_free(&r);
    return 0;
}

static void acme_free(acme_t *a)
{
    if (a->account_key)
        EVP_PKEY_free(a->account_key);
    if (a->ctx)
        SSL_CTX_free(a->ctx);
}

/* ------------------------------------------------------------------ */
/* Orders                                                              */
/* ------------------------------------------------------------------ */

static int make_csr(EVP_PKEY *key, char **hosts, int nhosts, buf_t *der_b64)
{
    X509_REQ *req = X509_REQ_new();
    X509_REQ_set_version(req, 0);
    X509_NAME *name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)hosts[0], -1, -1, 0);
    X509_REQ_set_pubkey(req, key);
    buf_t san;
    buf_init(&san);
    for (int i = 0; i < nhosts; i++)
        buf_printf(&san, "%sDNS:%s", i ? "," : "", hosts[i]);
    buf_append(&san, "", 1);
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san.data);
    buf_free(&san);
    if (ext) {
        sk_X509_EXTENSION_push(exts, ext);
        X509_REQ_add_extensions(req, exts);
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    int ok = X509_REQ_sign(req, key, EVP_sha256()) > 0;
    unsigned char *der = NULL;
    int dl = ok ? i2d_X509_REQ(req, &der) : -1;
    X509_REQ_free(req);
    if (dl <= 0)
        return -1;
    b64url(der, (size_t)dl, der_b64);
    OPENSSL_free(der);
    return 0;
}

static int poll_status(acme_t *a, const char *url, const char *what, char *status, size_t sl, aresp_t *last, int max_tries)
{
    for (int i = 0; i < max_tries; i++) {
        aresp_free(last);
        if (acme_post(a, url, NULL, last) < 0)
            return -1;
        if (last->status >= 400) {
            acme_log_problem(what, last);
            return -1;
        }
        jstr(last->body.data, "status", status, sl);
        if (strcmp(status, "pending") != 0 && strcmp(status, "processing") != 0)
            return 0;
        const char *ra = aresp_hdr(last, "Retry-After");
        int wait = ra ? atoi(ra) : 2;
        if (wait < 1 || wait > 10)
            wait = 2;
        sleep((unsigned)wait);
    }
    return 0;
}

static volatile sig_atomic_t manager_stop;

/* run "<script> <action> <domain> <txt>" and wait for it */
static int run_dns_script(const char *script, const char *action, const char *domain, const char *txt)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execl(script, script, action, domain, txt, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        LOGE("acme: %s %s %s exited with %d", script, action, domain, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return -1;
    }
    return 0;
}

/* Obtain a certificate for the hosts and store it under certs/<hosts[0]>. */
static int acme_obtain(acme_t *a, char **hosts, int nhosts)
{
    const config_t *cfg = a->cfg;
    aresp_t r;
    memset(&r, 0, sizeof r);
    buf_t payload;
    buf_init(&payload);
    buf_puts(&payload, "{\"identifiers\":[");
    for (int i = 0; i < nhosts; i++)
        buf_printf(&payload, "%s{\"type\":\"dns\",\"value\":\"%s\"}", i ? "," : "", hosts[i]);
    buf_puts(&payload, "]}");
    buf_append(&payload, "", 1);
    int rc = acme_post(a, a->dir_new_order, payload.data, &r);
    buf_free(&payload);
    if (rc < 0)
        return -1;
    if (r.status != 201) {
        acme_log_problem("new order", &r);
        aresp_free(&r);
        return -1;
    }
    char order_url[1024] = "", finalize[1024] = "";
    const char *loc = aresp_hdr(&r, "Location");
    if (loc)
        snprintf(order_url, sizeof order_url, "%s", loc);
    jstr(r.body.data, "finalize", finalize, sizeof finalize);
    char **authz = NULL;
    int nauthz = 0;
    for (int i = 0;; i++) {
        char path[32], url[1024];
        snprintf(path, sizeof path, "authorizations[%d]", i);
        if (!jstr(r.body.data, path, url, sizeof url))
            break;
        authz = xrealloc(authz, sizeof(char *) * (size_t)(nauthz + 1));
        authz[nauthz++] = xstrdup(url);
    }
    aresp_free(&r);
    if (!order_url[0] || !finalize[0] || nauthz == 0) {
        LOGE("acme: order response incomplete");
        goto fail;
    }
    char chdir_[1024];
    snprintf(chdir_, sizeof chdir_, "%s/challenges", cfg->storage);
    mkdir_p(chdir_);

    /* authorizations: answer the http-01 challenge of each */
    for (int i = 0; i < nauthz; i++) {
        if (acme_post(a, authz[i], NULL, &r) < 0)
            goto fail;
        if (r.status >= 400) {
            acme_log_problem("authorization", &r);
            goto fail;
        }
        char status[32] = "";
        jstr(r.body.data, "status", status, sizeof status);
        char ident[256] = "";
        jstr(r.body.data, "identifier.value", ident, sizeof ident);
        if (strcmp(status, "valid") == 0) {
            aresp_free(&r);
            continue;
        }
        int is_wild = 0;
        {
            char w[8] = "";
            jstr(r.body.data, "wildcard", w, sizeof w);
            is_wild = strcmp(w, "true") == 0;
        }
        const char *want = cfg->acme_challenge == 2 || is_wild ? "dns-01" : cfg->acme_challenge == 1 ? "tls-alpn-01" : "http-01";
        char token[256] = "", curl_[1024] = "";
        for (int k = 0;; k++) {
            char path[64], type[32];
            snprintf(path, sizeof path, "challenges[%d].type", k);
            if (!jstr(r.body.data, path, type, sizeof type))
                break;
            if (strcmp(type, want) == 0) {
                snprintf(path, sizeof path, "challenges[%d].token", k);
                jstr(r.body.data, path, token, sizeof token);
                snprintf(path, sizeof path, "challenges[%d].url", k);
                jstr(r.body.data, path, curl_, sizeof curl_);
                break;
            }
        }
        aresp_free(&r);
        if (!token[0] || !curl_[0]) {
            LOGE("acme: no %s challenge offered for %s", want, ident);
            goto fail;
        }
        char keyauth[512], cpath[2048], txt[80] = "";
        snprintf(keyauth, sizeof keyauth, "%s.%s", token, a->thumbprint);
        if (strcmp(want, "http-01") == 0) {
            snprintf(cpath, sizeof cpath, "%s/%s", chdir_, token);
        } else if (strcmp(want, "tls-alpn-01") == 0) {
            char lower[256];
            snprintf(lower, sizeof lower, "%s", ident);
            for (char *q = lower; *q; q++)
                *q = (char)tolower((unsigned char)*q);
            char d2[1100];
            snprintf(d2, sizeof d2, "%s/tls-alpn", chdir_);
            mkdir_p(d2);
            snprintf(cpath, sizeof cpath, "%s/%s", d2, lower);
        } else {
            /* dns-01: TXT value is base64url(SHA-256(keyauth)) */
            unsigned char dg[32];
            unsigned int dl = 0;
            EVP_Digest(keyauth, strlen(keyauth), dg, &dl, EVP_sha256(), NULL);
            base64_encode(dg, 32, txt, 1);
            cpath[0] = 0;
            if (!cfg->acme_dns_script) {
                LOGE("acme: dns-01 for %s needs 'acme_dns_script' in the global options", ident);
                goto fail;
            }
        }
        if (cpath[0] && write_file_atomic(cpath, keyauth, strlen(keyauth), 0644) < 0) {
            LOGE("acme: cannot write challenge file %s: %s", cpath, strerror(errno));
            goto fail;
        }
        if (!cpath[0]) {
            if (run_dns_script(cfg->acme_dns_script, "present", ident, txt) != 0) {
                LOGE("acme: dns script failed to present the record for %s", ident);
                goto fail;
            }
            LOGI("acme: dns-01 record presented for %s; waiting %.0fs for propagation", ident, cfg->acme_dns_propagation);
            for (double t = 0; t < cfg->acme_dns_propagation && !manager_stop; t += 1)
                sleep(1);
        }
        LOGI("acme: answering %s challenge for %s", want, ident);
        if (acme_post(a, curl_, "{}", &r) < 0) {
            if (cpath[0]) unlink(cpath); else run_dns_script(cfg->acme_dns_script, "cleanup", ident, txt);
            goto fail;
        }
        if (r.status >= 400) {
            acme_log_problem("challenge", &r);
            if (cpath[0]) unlink(cpath); else run_dns_script(cfg->acme_dns_script, "cleanup", ident, txt);
            goto fail;
        }
        aresp_free(&r);
        status[0] = 0;
        rc = poll_status(a, authz[i], "authorization", status, sizeof status, &r, 30);
        if (cpath[0])
            unlink(cpath);
        else
            run_dns_script(cfg->acme_dns_script, "cleanup", ident, txt);
        if (rc < 0)
            goto fail;
        if (strcmp(status, "valid") != 0) {
            char detail[512] = "";
            for (int k = 0; k < 8; k++) {
                char path[64];
                snprintf(path, sizeof path, "challenges[%d].error.detail", k);
                if (jstr(r.body.data, path, detail, sizeof detail))
                    break;
            }
            LOGE("acme: authorization for %s ended with status '%s' %s", ident, status, detail);
            goto fail;
        }
        aresp_free(&r);
    }

    /* finalize with a CSR for a fresh key */
    LOGD("acme: all authorizations valid, finalizing order %s", order_url);
    EVP_PKEY *key = EVP_EC_gen("P-256");
    if (!key)
        goto fail;
    buf_t csr;
    buf_init(&csr);
    if (make_csr(key, hosts, nhosts, &csr) < 0) {
        EVP_PKEY_free(key);
        buf_free(&csr);
        goto fail;
    }
    buf_init(&payload);
    buf_printf(&payload, "{\"csr\":\"%.*s\"}", (int)csr.len, csr.data);
    buf_append(&payload, "", 1);
    buf_free(&csr);
    rc = acme_post(a, finalize, payload.data, &r);
    buf_free(&payload);
    if (rc < 0 || r.status >= 400) {
        if (rc == 0)
            acme_log_problem("finalize", &r);
        EVP_PKEY_free(key);
        goto fail;
    }
    char status[32] = "";
    jstr(r.body.data, "status", status, sizeof status);
    if (strcmp(status, "valid") != 0) {
        if (poll_status(a, order_url, "order", status, sizeof status, &r, 30) < 0 || strcmp(status, "valid") != 0) {
            LOGE("acme: order ended with status '%s'", status);
            EVP_PKEY_free(key);
            goto fail;
        }
    }
    char cert_url[1024] = "";
    jstr(r.body.data, "certificate", cert_url, sizeof cert_url);
    aresp_free(&r);
    LOGD("acme: downloading certificate %s", cert_url);
    if (!cert_url[0] || acme_post(a, cert_url, NULL, &r) < 0 || r.status != 200) {
        LOGE("acme: certificate download failed");
        EVP_PKEY_free(key);
        goto fail;
    }
    /* store */
    char dir[1024], certp[2048], keyp[2048];
    snprintf(dir, sizeof dir, "%s/certs/%s", cfg->storage, hosts[0]);
    mkdir_p(dir);
    snprintf(certp, sizeof certp, "%s/cert.pem", dir);
    snprintf(keyp, sizeof keyp, "%s/key.pem", dir);
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    char *pem = NULL;
    long pl = BIO_get_mem_data(bio, &pem);
    int ok = write_file_atomic(keyp, pem, (size_t)pl, 0600) == 0 &&
             write_file_atomic(certp, r.body.data, r.body.len, 0644) == 0;
    BIO_free(bio);
    EVP_PKEY_free(key);
    aresp_free(&r);
    if (!ok) {
        LOGE("acme: cannot store certificate in %s: %s", dir, strerror(errno));
        goto fail;
    }
    LOGI("acme: obtained certificate for %s%s (%d name%s)", hosts[0], nhosts > 1 ? " and others" : "", nhosts, nhosts == 1 ? "" : "s");
    for (int i = 0; i < nauthz; i++)
        free(authz[i]);
    free(authz);
    return 0;
fail:
    aresp_free(&r);
    for (int i = 0; i < nauthz; i++)
        free(authz[i]);
    free(authz);
    return -1;
}

/* seconds until the stored certificate expires, or -1 if none/unreadable; also
 * reports whether it covers all hosts */
static double cert_remaining(const config_t *cfg, char **hosts, int nhosts, int *covers)
{
    char certp[2048];
    snprintf(certp, sizeof certp, "%s/certs/%s/cert.pem", cfg->storage, hosts[0]);
    FILE *f = fopen(certp, "r");
    if (!f)
        return -1;
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!x)
        return -1;
    int days = 0, secs = 0;
    ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(x));
    double remaining = (double)days * 86400 + secs;
    *covers = 1;
    for (int i = 0; i < nhosts; i++)
        if (X509_check_host(x, hosts[i], 0, 0, NULL) != 1)
            *covers = 0;
    X509_free(x);
    return remaining;
}

/* ------------------------------------------------------------------ */
/* Manager process                                                     */
/* ------------------------------------------------------------------ */

static pid_t manager_pid;

static void manager_sig(int sig)
{
    (void)sig;
    manager_stop = 1;
}

static int site_is_local(const server_t *s)
{
    for (int h = 0; h < s->nhosts; h++) {
        const char *x = s->hosts[h];
        size_t n = strlen(x);
        if (!(strcasecmp(x, "localhost") == 0 || (n > 10 && strcasecmp(x + n - 10, ".localhost") == 0)))
            return 0;
    }
    return 1;
}

static int manager_main(config_t *cfg)
{
    signal(SIGTERM, manager_sig);
    signal(SIGINT, manager_sig);
    signal(SIGHUP, SIG_IGN);
    pid_t parent = getppid();
    unsigned backoff = 60;
    for (;;) {
        acme_t a;
        int inited = 0;
        int any_failed = 0, any_obtained = 0;
        for (int i = 0; i < cfg->nservers && !manager_stop; i++) {
            server_t *s = cfg->servers[i];
            if (s->tls_mode != TLS_AUTO || s->nhosts == 0 || site_is_local(s) || s->is_admin)
                continue;
            int wildcard = 0;
            for (int h = 0; h < s->nhosts; h++)
                if (strchr(s->hosts[h], '*'))
                    wildcard = 1;
            if (wildcard && !cfg->acme_dns_script) {
                LOGE("acme: site %s: wildcard names need dns-01 validation; set 'acme_dns_script' or use 'tls <cert> <key>'", s->hosts[0]);
                continue;
            }
            int covers = 0;
            double rem = cert_remaining(cfg, s->hosts, s->nhosts, &covers);
            if (rem >= ACME_RENEW_BEFORE && covers)
                continue;
            if (!inited) {
                if (acme_init(&a, cfg) < 0) {
                    any_failed = 1;
                    break;
                }
                inited = 1;
            }
            LOGI("acme: %s certificate for %s", rem < 0 ? "obtaining" : "renewing", s->hosts[0]);
            if (acme_obtain(&a, s->hosts, s->nhosts) == 0)
                any_obtained = 1;
            else
                any_failed = 1;
        }
        if (inited)
            acme_free(&a);
        if (manager_stop)
            break;
        if (any_obtained && parent > 1)
            kill(parent, SIGHUP);
        unsigned wait = ACME_CHECK_INTERVAL;
        if (any_failed) {
            wait = backoff;
            backoff = backoff < 3600 ? backoff * 2 : 3600;
            LOGW("acme: will retry in %u seconds", wait);
        } else {
            backoff = 60;
        }
        for (unsigned t = 0; t < wait && !manager_stop; t++)
            sleep(1);
        if (manager_stop)
            break;
    }
    return 0;
}

int acme_manager_start(config_t *cfg)
{
    int needed = 0;
    for (int i = 0; i < cfg->nservers; i++) {
        server_t *s = cfg->servers[i];
        if (s->tls_mode == TLS_AUTO && s->nhosts && !site_is_local(s))
            needed = 1;
    }
    if (!needed || cfg->acme_disabled == 1)
        return 0;
    if (mkdir_p(cfg->storage) < 0) {
        LOGE("acme: cannot create storage directory %s: %s", cfg->storage, strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        LOGE("acme: fork: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* child: drop inherited sockets, run the manager */
        for (int fd = 3; fd < 65536; fd++)
            close(fd);
        _exit(manager_main(cfg));
    }
    manager_pid = pid;
    LOGI("acme: certificate manager started (pid %d, CA %s)", (int)pid, cfg->acme_ca);
    return 0;
}

void acme_manager_stop(void)
{
    if (manager_pid > 0) {
        kill(manager_pid, SIGTERM);
        waitpid(manager_pid, NULL, 0);
        manager_pid = 0;
    }
}

#else /* !LIMER_TLS */

int acme_manager_start(config_t *cfg) { (void)cfg; return 0; }
void acme_manager_stop(void) {}

#endif
