/*
 * h3.inc - HTTP/3 over QUIC (included by proxy.c; needs ngtcp2 and nghttp3
 * with the GnuTLS crypto backend, plus TLS for the certificates).
 *
 * Every HTTPS bind also gets a UDP socket on the same address and port. QUIC
 * connections are found by connection ID. Each request stream becomes a
 * virtual conn_t exactly like an HTTP/2 stream: its headers and body are turned
 * into an HTTP/1.1 request in the stream's rbuf for the normal pipeline, and the
 * HTTP/1.1 response the handlers write into its wbuf is re-framed for nghttp3.
 * nghttp3 keeps response bytes until the peer acknowledges them, so they are
 * copied into chunks that are freed on acknowledgement.
 *
 * Certificates come from each site's OpenSSL context (certificate files,
 * `tls internal` and ACME alike) and are loaded into one GnuTLS credential set
 * per bind, from which GnuTLS picks by SNI. Clients are told not to migrate, so
 * SO_REUSEPORT keeps every connection on the worker that accepted it. Sending is
 * deferred to the end of each event batch, never done from inside a callback.
 */
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <nghttp3/nghttp3.h>
#include <openssl/pem.h>

#define H3_SCID_LEN    18
#define H3_TX_PKT      1452
#define H3_MAX_STREAMS 100
#define H3_CHUNK       16384
#define H3_CID_BUCKETS 4096
#define H3_MAX_CIDS    16
#define H3_SOCKBUF     (4 << 20)   /* UDP socket buffers, per direction */

/* GnuTLS credentials of one bind; refcounted so a reload can swap them while
 * older connections keep using theirs. */
typedef struct h3cred {
    gnutls_certificate_credentials_t cred;
    int refs;
} h3cred_t;

typedef struct h3sock {
    ev_t ev;                       /* the UDP socket */
    char *addr;                    /* bind string, as on the TCP listener */
    struct sockaddr_storage bound;
    socklen_t boundlen;
    int wildcard;                  /* bound to any address: use pktinfo for the local side */
    h3cred_t *cred;
    int seen;                      /* still wanted by the current config */
    int retiring;                  /* no new connections; closed once its connections end */
    int nconns;
    struct h3sock *next;
} h3sock_t;

typedef struct h3chunk {           /* response bytes handed to nghttp3, kept until acknowledged */
    struct h3chunk *next;
    size_t len, acked;
    uint8_t data[];
} h3chunk_t;

typedef struct h3orphan {          /* chunks of a stream limer closed early, freed when QUIC closes it */
    int64_t sid;
    h3chunk_t *chunks;
    struct h3orphan *next;
} h3orphan_t;

typedef struct h3conn {
    ngtcp2_conn *qc;
    gnutls_session_t tls;
    nghttp3_conn *h3;
    ngtcp2_crypto_conn_ref ref;
    ngtcp2_ccerr err;
    h3sock_t *sock;
    h3cred_t *cred;
    config_t *cfg;
    struct sockaddr_storage local, remote;
    socklen_t locallen, remotelen;
    char peer_ip[64], peer_str[80], sni[256];
    ngtcp2_cid cids[H3_MAX_CIDS];
    int ncids;
    conn_t **streams;
    int nstreams, cap;
    h3orphan_t *orphans;
    ngtcp2_tstamp expiry;
    int want_send;
    int closing, draining, dead, goaway;
    double close_until;
    uint8_t closebuf[H3_TX_PKT];
    size_t closelen;
    int ip_tracked;
    struct h3conn *next;
} h3conn_t;

typedef struct h3cid {
    ngtcp2_cid cid;
    h3conn_t *c;
    struct h3cid *next;
} h3cid_t;

static h3sock_t *g_h3_socks;
static h3conn_t *g_h3_conns;
static h3cid_t *g_h3_cids[H3_CID_BUCKETS];
static uint8_t g_h3_rx[65536];

static void h3_conn_close(h3conn_t *c);
static void h3_conn_free(h3conn_t *c);

static ngtcp2_tstamp h3_ts(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

static void h3_random(void *p, size_t n)
{
    gnutls_rnd(GNUTLS_RND_RANDOM, p, n);
}

/* ---- connection-ID table ---- */

static unsigned h3_cid_bucket(const uint8_t *d, size_t n)
{
    return (unsigned)(hash64(d, n) & (H3_CID_BUCKETS - 1));
}

static h3conn_t *h3_cid_find(const uint8_t *d, size_t n)
{
    for (h3cid_t *e = g_h3_cids[h3_cid_bucket(d, n)]; e; e = e->next)
        if (e->cid.datalen == n && memcmp(e->cid.data, d, n) == 0)
            return e->c;
    return NULL;
}

static int h3_cid_add(h3conn_t *c, const ngtcp2_cid *cid)
{
    if (c->ncids >= H3_MAX_CIDS || h3_cid_find(cid->data, cid->datalen))
        return -1;
    h3cid_t *e = xcalloc(1, sizeof *e);
    e->cid = *cid;
    e->c = c;
    unsigned b = h3_cid_bucket(cid->data, cid->datalen);
    e->next = g_h3_cids[b];
    g_h3_cids[b] = e;
    c->cids[c->ncids++] = *cid;
    return 0;
}

static void h3_cid_del(h3conn_t *c, const ngtcp2_cid *cid)
{
    unsigned b = h3_cid_bucket(cid->data, cid->datalen);
    for (h3cid_t **pp = &g_h3_cids[b]; *pp; pp = &(*pp)->next) {
        h3cid_t *e = *pp;
        if (e->c == c && e->cid.datalen == cid->datalen && memcmp(e->cid.data, cid->data, cid->datalen) == 0) {
            *pp = e->next;
            free(e);
            break;
        }
    }
    for (int i = 0; i < c->ncids; i++)
        if (c->cids[i].datalen == cid->datalen && memcmp(c->cids[i].data, cid->data, cid->datalen) == 0) {
            c->cids[i] = c->cids[--c->ncids];
            break;
        }
}

/* ---- credentials ---- */

static void h3_cred_unref(h3cred_t *hc)
{
    if (hc && --hc->refs == 0) {
        gnutls_certificate_free_credentials(hc->cred);
        free(hc);
    }
}

static void h3_pem_append(buf_t *out, X509 *x, EVP_PKEY *k)
{
    BIO *b = BIO_new(BIO_s_mem());
    if (!b)
        return;
    int ok = x ? PEM_write_bio_X509(b, x) : PEM_write_bio_PrivateKey(b, k, NULL, NULL, 0, NULL, NULL);
    char *p = NULL;
    long n = BIO_get_mem_data(b, &p);
    if (ok && n > 0)
        buf_append(out, p, (size_t)n);
    BIO_free(b);
}

/* Load the certificate and key of every TLS site on this bind into GnuTLS. */
static h3cred_t *h3_cred_build(listener_t *l)
{
    h3cred_t *hc = xcalloc(1, sizeof *hc);
    if (gnutls_certificate_allocate_credentials(&hc->cred) < 0) {
        free(hc);
        return NULL;
    }
    hc->refs = 1;
    int loaded = 0;
    for (int i = 0; i < l->nservers; i++) {
        SSL_CTX *ctx = l->servers[i]->ssl_ctx;
        if (!ctx)
            continue;
        X509 *leaf = SSL_CTX_get0_certificate(ctx);
        EVP_PKEY *key = SSL_CTX_get0_privatekey(ctx);
        if (!leaf || !key)
            continue;
        buf_t cert, pk;
        buf_init(&cert);
        buf_init(&pk);
        h3_pem_append(&cert, leaf, NULL);
        STACK_OF(X509) *chain = NULL;
        SSL_CTX_get0_chain_certs(ctx, &chain);
        if (!chain || sk_X509_num(chain) == 0)
            SSL_CTX_get_extra_chain_certs(ctx, &chain);
        for (int k = 0; chain && k < sk_X509_num(chain); k++)
            h3_pem_append(&cert, sk_X509_value(chain, k), NULL);
        h3_pem_append(&pk, NULL, key);
        gnutls_datum_t cd = { (unsigned char *)buf_rptr(&cert), (unsigned)buf_readable(&cert) };
        gnutls_datum_t kd = { (unsigned char *)buf_rptr(&pk), (unsigned)buf_readable(&pk) };
        if (cd.size && kd.size &&
            gnutls_certificate_set_x509_key_mem2(hc->cred, &cd, &kd, GNUTLS_X509_FMT_PEM, NULL, 0) >= 0)
            loaded++;
        else
            LOGW("http/3: cannot load the certificate of %s", l->servers[i]->nhosts ? l->servers[i]->hosts[0] : l->addr);
        buf_free(&cert);
        buf_free(&pk);
    }
    if (!loaded) {
        h3_cred_unref(hc);
        return NULL;
    }
    return hc;
}

/* ---- UDP sockets ---- */

static void h3_sock_cb(ev_t *e, uint32_t events);

static void h3_sock_destroy(ev_t *e)
{
    h3sock_t *hs = (h3sock_t *)e;
    h3_cred_unref(hs->cred);
    free(hs->addr);
    free(hs);
}

static h3sock_t *h3_sock_open(const char *addr, char *err, size_t errlen)
{
    char *host;
    int port;
    if (parse_hostport(addr, &host, &port, 0) < 0) {
        snprintf(err, errlen, "invalid address '%s'", addr);
        return NULL;
    }
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    int rc = getaddrinfo(*host ? host : NULL, portstr, &hints, &res);
    if (rc != 0) {
        snprintf(err, errlen, "cannot resolve '%s': %s", addr, gai_strerror(rc));
        free(host);
        return NULL;
    }
    int fd = -1, last_errno = 0, family = 0;
    for (int pass = 0; pass < 2 && fd < 0; pass++) {
        for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
            if ((pass == 0) != (ai->ai_family == AF_INET6))
                continue;
            int s = socket(ai->ai_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (s < 0) {
                last_errno = errno;
                continue;
            }
            int one = 1, zero = 0;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
            setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
            if (ai->ai_family == AF_INET6) {
                setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
                setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof one);
            } else {
                setsockopt(s, IPPROTO_IP, IP_PKTINFO, &one, sizeof one);
            }
            /* The kernel default (~208 KB) overflows when many connections burst
             * at once, and each dropped datagram costs a QUIC loss-recovery
             * timeout. The FORCE variants pass net.core.[rw]mem_max as root. */
            int buf = H3_SOCKBUF;
#ifdef SO_RCVBUFFORCE
            if (setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &buf, sizeof buf) < 0)
#endif
                setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
#ifdef SO_SNDBUFFORCE
            if (setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof buf) < 0)
#endif
                setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
            if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
                last_errno = errno;
                close(s);
                continue;
            }
            fd = s;
            family = ai->ai_family;
            break;
        }
    }
    freeaddrinfo(res);
    if (fd < 0) {
        snprintf(err, errlen, "cannot bind udp '%s': %s", addr, strerror(last_errno ? last_errno : EADDRNOTAVAIL));
        free(host);
        return NULL;
    }
    (void)family;
    h3sock_t *hs = xcalloc(1, sizeof *hs);
    hs->ev.fd = fd;
    hs->ev.cb = h3_sock_cb;
    hs->ev.destroy = h3_sock_destroy;
    hs->addr = xstrdup(addr);
    hs->wildcard = !*host;
    hs->boundlen = sizeof hs->bound;
    getsockname(fd, (struct sockaddr *)&hs->bound, &hs->boundlen);
    free(host);
    ev_add(&hs->ev, EPOLLIN);
    return hs;
}

/* Match the UDP sockets to the HTTPS binds of the running config; called at
 * start and after every reload (certificates may have been renewed). */
static void h3_apply(void)
{
    for (h3sock_t *hs = g_h3_socks; hs; hs = hs->next)
        hs->seen = 0;
    if (g_cfg->http3 && !g_shutting_down) {
        for (listener_t *l = g_listeners; l; l = l->next) {
            if (!l->tls)
                continue;
            h3sock_t *hs = g_h3_socks;
            while (hs && strcmp(hs->addr, l->addr) != 0)
                hs = hs->next;
            if (!hs) {
                char err[256];
                hs = h3_sock_open(l->addr, err, sizeof err);
                if (!hs) {
                    LOGE("http/3: %s", err);
                    continue;
                }
                hs->next = g_h3_socks;
                g_h3_socks = hs;
                LOGI("http/3: listening on %s (udp)", l->addr);
            }
            h3cred_t *cred = h3_cred_build(l);
            if (cred) {
                h3_cred_unref(hs->cred);
                hs->cred = cred;
            }
            hs->seen = 1;
            hs->retiring = 0;
        }
    }
    g_h3_live = 0;
    for (h3sock_t *hs = g_h3_socks; hs; hs = hs->next) {
        if (!hs->seen)
            hs->retiring = 1;
        else
            g_h3_live = 1;
    }
}

static void h3_send(h3sock_t *hs, const ngtcp2_path *path, const uint8_t *data, size_t len)
{
    struct iovec iov = { (void *)data, len };
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_name = path->remote.addr;
    mh.msg_namelen = path->remote.addrlen;
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    union {
        struct cmsghdr h;
        uint8_t b[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    } ctl;
    if (hs->wildcard && path->local.addr) {
        /* answer from the address the client sent to */
        memset(&ctl, 0, sizeof ctl);
        mh.msg_control = &ctl;
        struct cmsghdr *cm = &ctl.h;
        if (path->local.addr->sa_family == AF_INET6) {
            cm->cmsg_level = IPPROTO_IPV6;
            cm->cmsg_type = IPV6_PKTINFO;
            cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            struct in6_pktinfo pi;
            memset(&pi, 0, sizeof pi);
            pi.ipi6_addr = ((const struct sockaddr_in6 *)path->local.addr)->sin6_addr;
            memcpy(CMSG_DATA(cm), &pi, sizeof pi);
            mh.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
        } else {
            cm->cmsg_level = IPPROTO_IP;
            cm->cmsg_type = IP_PKTINFO;
            cm->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo pi;
            memset(&pi, 0, sizeof pi);
            pi.ipi_spec_dst = ((const struct sockaddr_in *)path->local.addr)->sin_addr;
            memcpy(CMSG_DATA(cm), &pi, sizeof pi);
            mh.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
        }
    }
    while (sendmsg(hs->ev.fd, &mh, 0) < 0 && errno == EINTR)
        ;
    /* EAGAIN and the like: QUIC recovers the loss */
}

/* ---- request streams ---- */

static void h3_streams_add(h3conn_t *c, conn_t *st)
{
    if (c->nstreams == c->cap) {
        c->cap = c->cap ? c->cap * 2 : 16;
        c->streams = xrealloc(c->streams, sizeof(conn_t *) * (size_t)c->cap);
    }
    c->streams[c->nstreams++] = st;
}

static void h3_streams_del(h3conn_t *c, conn_t *st)
{
    for (int i = 0; i < c->nstreams; i++)
        if (c->streams[i] == st) {
            c->streams[i] = c->streams[--c->nstreams];
            return;
        }
}

static void h3_chunks_free(h3chunk_t *k)
{
    while (k) {
        h3chunk_t *n = k->next;
        free(k);
        k = n;
    }
}

static void h3_chunks_ack(conn_t *st, uint64_t n)
{
    while (n && st->h3_out) {
        h3chunk_t *k = st->h3_out;
        size_t left = k->len - k->acked;
        size_t take = n < left ? (size_t)n : left;
        k->acked += take;
        n -= take;
        if (k->acked == k->len) {
            st->h3_out = k->next;
            if (!st->h3_out)
                st->h3_out_tail = NULL;
            free(k);
        }
    }
}

static conn_t *h3_stream_new(h3conn_t *c, int64_t sid)
{
    server_t *srv = select_server(c->cfg, c->sock->addr, c->sni[0] ? c->sni : NULL);
    if (!srv)
        return NULL;
    conn_t *st = xcalloc(1, sizeof *st);
    st->ev.fd = -1;
    st->ev.destroy = conn_destroy;
    st->h3c = c;
    st->h3_stream_id = sid;
    st->srv = srv;
    st->cfg = c->cfg;
    config_ref(st->cfg);
    snprintf(st->listen_addr, sizeof st->listen_addr, "%s", c->sock->addr);
    memcpy(&st->peer, &c->remote, sizeof st->peer);
    st->peerlen = c->remotelen;
    snprintf(st->peer_ip, sizeof st->peer_ip, "%s", c->peer_ip);
    snprintf(st->peer_str, sizeof st->peer_str, "%s", c->peer_str);
    buf_init(&st->rbuf);
    buf_init(&st->wbuf);
    buf_init(&st->enc_out);
    buf_init(&st->dechunk);
    buf_init(&st->h2_body);
    buf_init(&st->h2_trailers);
    buf_init(&st->h2_hdrs);
    buf_init(&st->h2_reqbody);
    st->file_fd = -1;
    st->h2_req_clen = -1;
    http_req_init(&st->req);
    st->state = CS_HEAD;
    st->deadline = g_now + st->srv->read_timeout;
    st->req_start = g_now;
    st->got_request_bytes = 1;
    conn_list_add(st);
    h3_streams_add(c, st);
    return st;
}

/* One request header field, as in HTTP/2 (RFC 9114 4.2 mirrors RFC 9113 8.2). */
static int h3_stream_header(conn_t *st, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen)
{
    if (namelen && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":method", 7) == 0)
            snprintf(st->h2_method, sizeof st->h2_method, "%.*s", (int)valuelen, value);
        else if (namelen == 5 && memcmp(name, ":path", 5) == 0)
            snprintf(st->h2_path, sizeof st->h2_path, "%.*s", (int)valuelen, value);
        else if (namelen == 10 && memcmp(name, ":authority", 10) == 0)
            snprintf(st->h2_authority, sizeof st->h2_authority, "%.*s", (int)valuelen, value);
        return 0;
    }
    if (namelen == 14 && memcmp(name, "content-length", 14) == 0) {
        char tmp[24];
        snprintf(tmp, sizeof tmp, "%.*s", (int)(valuelen < 23 ? valuelen : 23), value);
        char *end = NULL;
        long long v = strtoll(tmp, &end, 10);
        if (end && *end == 0 && v >= 0)
            st->h2_req_clen = v;
        return 0;
    }
    if ((namelen == 17 && memcmp(name, "transfer-encoding", 17) == 0) ||
        (namelen == 10 && memcmp(name, "connection", 10) == 0) ||
        (namelen == 7 && memcmp(name, "upgrade", 7) == 0) ||
        (namelen == 10 && memcmp(name, "keep-alive", 10) == 0) ||
        (namelen == 6 && memcmp(name, "expect", 6) == 0) ||
        (namelen == 4 && memcmp(name, "host", 4) == 0))
        return 0;
    if (namelen == 6 && memcmp(name, "cookie", 6) == 0) {
        if (buf_readable(&st->h2_cookie) > 0)
            buf_puts(&st->h2_cookie, "; ");
        buf_append(&st->h2_cookie, value, valuelen);
        return 0;
    }
    if (buf_readable(&st->h2_hdrs) > HTTP_MAX_HEAD)
        return -1;
    buf_append(&st->h2_hdrs, name, namelen);
    buf_puts(&st->h2_hdrs, ": ");
    buf_append(&st->h2_hdrs, value, valuelen);
    buf_puts(&st->h2_hdrs, "\r\n");
    return 0;
}

static void h3_stream_body_progress(conn_t *st)
{
    if (st->dead)
        return;
    if (st->state == CS_HEAD || st->state == CS_BODY)
        conn_process(st);
    else if (st->state == CS_UPSTREAM && st->body_stream && !st->body_done)
        conn_pump_body(st);
}

static void h3_stream_dispatch(conn_t *st, int has_body)
{
    if (!st->h2_method[0] || !st->h2_path[0]) {
        conn_send_error(st, 400, "missing :method or :path", 0);
        return;
    }
    buf_reset(&st->rbuf);
    buf_printf(&st->rbuf, "%s %s HTTP/1.1\r\n", st->h2_method, st->h2_path);
    if (st->h2_authority[0])
        buf_printf(&st->rbuf, "Host: %s\r\n", st->h2_authority);
    buf_append(&st->rbuf, buf_rptr(&st->h2_hdrs), buf_readable(&st->h2_hdrs));
    if (buf_readable(&st->h2_cookie) > 0) {
        buf_puts(&st->rbuf, "Cookie: ");
        buf_append(&st->rbuf, buf_rptr(&st->h2_cookie), buf_readable(&st->h2_cookie));
        buf_puts(&st->rbuf, "\r\n");
    }
    if (has_body && st->h2_req_clen >= 0) {
        buf_printf(&st->rbuf, "Content-Length: %lld\r\n", (long long)st->h2_req_clen);
        st->h2_req_raw = 1;
    } else if (has_body) {
        buf_puts(&st->rbuf, "Transfer-Encoding: chunked\r\n");
    } else if (strcmp(st->h2_method, "POST") == 0 || strcmp(st->h2_method, "PUT") == 0 || strcmp(st->h2_method, "PATCH") == 0) {
        buf_puts(&st->rbuf, "Content-Length: 0\r\n");
    }
    buf_puts(&st->rbuf, "\r\n");
    buf_reset(&st->h2_hdrs);
    buf_reset(&st->h2_cookie);
    st->h2_body_started = 1;
    st->h3_has_body = has_body;
    if (!has_body)
        st->rd_eof = 1;
    conn_process(st);
}

/* Streamed-body bytes were forwarded upstream: give the client flow-control credit back. */
static void h3_stream_consumed(conn_t *st, size_t n)
{
    h3conn_t *c = st->h3c;
    if (!c || c->dead || st->h2_detached)
        return;
    if (n > st->h2_unconsumed)
        n = st->h2_unconsumed;
    if (n == 0)
        return;
    st->h2_unconsumed -= n;
    ngtcp2_conn_extend_max_stream_offset(c->qc, st->h3_stream_id, n);
    ngtcp2_conn_extend_max_offset(c->qc, n);
    c->want_send = 1;
}

/* ---- response ---- */

static int h3_submit_trailers(h3conn_t *c, int64_t sid, buf_t *raw)
{
    if (buf_readable(raw) == 0)
        return 0;
    buf_append(raw, "", 1);
    char *text = buf_rptr(raw), *save = NULL;
    nghttp3_nv nva[32];
    int n = 0;
    for (char *line = strtok_r(text, "\r\n", &save); line && n < 32; line = strtok_r(NULL, "\r\n", &save)) {
        char *colon = strchr(line, ':');
        if (!colon || colon == line)
            continue;
        *colon = 0;
        char *v = colon + 1;
        while (*v == ' ' || *v == '\t')
            v++;
        if (http_hdr_is_hop_by_hop(line))
            continue;
        for (char *p = line; *p; p++)
            *p = (char)tolower((unsigned char)*p);
        nva[n].name = (const uint8_t *)line;
        nva[n].namelen = strlen(line);
        nva[n].value = (const uint8_t *)v;
        nva[n].valuelen = strlen(v);
        nva[n].flags = NGHTTP3_NV_FLAG_NONE;
        n++;
    }
    int rc = n ? nghttp3_conn_submit_trailers(c->h3, sid, nva, (size_t)n) : -1;
    buf_reset(raw);
    return rc == 0;
}

static nghttp3_ssize h3_read_data(nghttp3_conn *h3, int64_t sid, nghttp3_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *ud, void *sud)
{
    (void)h3; (void)veccnt;
    h3conn_t *c = ud;
    conn_t *st = sud;
    if (!st || st->dead) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    buf_t *src = &st->wbuf;
    int eof;
    if (st->h2_chunked) {
        if (buf_readable(&st->wbuf) > 0 && !st->h2_cs.done) {
            size_t consumed = 0;
            st->h2_cs.trailers = &st->h2_trailers;
            if (http_chunk_scan(&st->h2_cs, buf_rptr(&st->wbuf), buf_readable(&st->wbuf), &consumed, &st->h2_body) < 0)
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            buf_consume(&st->wbuf, consumed);
        }
        src = &st->h2_body;
    }
    size_t n = buf_readable(src);
    if (n > H3_CHUNK)
        n = H3_CHUNK;
    if (st->h2_chunked)
        eof = st->h2_cs.done && buf_readable(&st->h2_body) == n;
    else
        eof = st->h2_eof && buf_readable(&st->wbuf) == n;
    if (n == 0 && !eof) {
        st->h2_deferred = 1;
        return NGHTTP3_ERR_WOULDBLOCK;
    }
    nghttp3_ssize nvec = 0;
    if (n > 0) {
        h3chunk_t *k = xmalloc(sizeof *k + n);
        k->next = NULL;
        k->len = n;
        k->acked = 0;
        memcpy(k->data, buf_rptr(src), n);
        buf_consume(src, n);
        if (st->h3_out_tail)
            st->h3_out_tail->next = k;
        else
            st->h3_out = k;
        st->h3_out_tail = k;
        vec[0].base = k->data;
        vec[0].len = n;
        nvec = 1;
    }
    if (eof) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        if (st->h2_chunked && buf_readable(&st->h2_trailers) > 0 && h3_submit_trailers(c, sid, &st->h2_trailers))
            *pflags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
    }
    return nvec;
}

/* The handlers wrote (more of) an HTTP/1.1 response into wbuf: submit or resume it.
 * Packets go out at the end of the event batch. */
static void h3_stream_flush(conn_t *st)
{
    h3conn_t *c = st->h3c;
    if (!c || c->dead || c->closing || !c->h3 || st->dead || st->h2_detached)
        return;
    if (!st->h2_submitted) {
        http_resp_t resp;
        http_resp_init(&resp);
        size_t consumed = 0;
        int rc = http_parse_response_head(&resp, buf_rptr(&st->wbuf), buf_readable(&st->wbuf), &consumed);
        if (rc == 0)
            return;
        if (rc < 0) {
            http_resp_free(&resp);
            ngtcp2_conn_shutdown_stream(c->qc, 0, st->h3_stream_id, NGHTTP3_H3_INTERNAL_ERROR);
            c->want_send = 1;
            return;
        }
        buf_consume(&st->wbuf, consumed);
        st->h2_chunked = resp.chunked;
        memset(&st->h2_cs, 0, sizeof st->h2_cs);
        nghttp3_nv *nva = xcalloc((size_t)resp.nhdr + 1, sizeof(nghttp3_nv));
        char status[8];
        snprintf(status, sizeof status, "%d", resp.status);
        int nv = 0;
        nva[nv].name = (const uint8_t *)":status";
        nva[nv].namelen = 7;
        nva[nv].value = (const uint8_t *)status;
        nva[nv].valuelen = strlen(status);
        nva[nv].flags = NGHTTP3_NV_FLAG_NONE;
        nv++;
        for (int i = 0; i < resp.nhdr; i++) {
            char *n = resp.hdrs[i].name;
            if (http_hdr_is_hop_by_hop(n) || strcasecmp(n, "Keep-Alive") == 0 || strcasecmp(n, "Alt-Svc") == 0)
                continue;
            for (char *p = n; *p; p++)
                *p = (char)tolower((unsigned char)*p);
            nva[nv].name = (const uint8_t *)n;
            nva[nv].namelen = strlen(n);
            nva[nv].value = (const uint8_t *)resp.hdrs[i].value;
            nva[nv].valuelen = strlen(resp.hdrs[i].value);
            nva[nv].flags = NGHTTP3_NV_FLAG_NONE;
            nv++;
        }
        int bodiless = resp.status / 100 == 1 || resp.status == 204 || resp.status == 304 ||
                       (st->req.method && strcmp(st->req.method, "HEAD") == 0);
        if (!bodiless && !resp.chunked && resp.content_length == 0)
            bodiless = 1;
        if (!bodiless && resp.chunked && buf_readable(&st->wbuf) == 5 && memcmp(buf_rptr(&st->wbuf), "0\r\n\r\n", 5) == 0) {
            buf_consume(&st->wbuf, 5);
            bodiless = 1;
        }
        nghttp3_data_reader dr = { h3_read_data };
        int r = nghttp3_conn_submit_response(c->h3, st->h3_stream_id, nva, (size_t)nv, bodiless ? NULL : &dr);
        free(nva);
        http_resp_free(&resp);
        if (r != 0) {
            LOGW("http/3: submit_response failed: %s", nghttp3_strerror(r));
            conn_close(st);
            return;
        }
        st->h2_submitted = 1;
        st->resp_committed = 1;
        if (bodiless)
            st->h2_eof = 1;
    } else if (st->h2_deferred) {
        st->h2_deferred = 0;
        nghttp3_conn_resume_stream(c->h3, st->h3_stream_id);
    }
    c->want_send = 1;
}

/* Called from conn_close() for a stream. */
static void h3_stream_close(conn_t *st)
{
    h3conn_t *c = st->h3c;
    if (!c) {
        h3_chunks_free(st->h3_out);
        st->h3_out = st->h3_out_tail = NULL;
        return;
    }
    h3_streams_del(c, st);
    if (!c->dead && !st->h2_detached && c->h3) {
        /* closed by limer before QUIC was done with the stream: reset it, and keep
         * the bytes ngtcp2 may still reference until the stream is gone */
        nghttp3_conn_set_stream_user_data(c->h3, st->h3_stream_id, NULL);
        if (!st->h2_eof || !st->h2_submitted)
            ngtcp2_conn_shutdown_stream(c->qc, 0, st->h3_stream_id, NGHTTP3_H3_INTERNAL_ERROR);
        if (st->h3_out) {
            h3orphan_t *o = xcalloc(1, sizeof *o);
            o->sid = st->h3_stream_id;
            o->chunks = st->h3_out;
            o->next = c->orphans;
            c->orphans = o;
        }
        c->want_send = 1;
    } else {
        h3_chunks_free(st->h3_out);
    }
    st->h3_out = st->h3_out_tail = NULL;
    st->h3c = NULL;
}

/* ---- nghttp3 callbacks ---- */

static int h3_cb_acked(nghttp3_conn *h3, int64_t sid, uint64_t datalen, void *ud, void *sud)
{
    (void)h3; (void)sid; (void)ud;
    if (sud)
        h3_chunks_ack(sud, datalen);
    return 0;
}

static int h3_cb_stream_close(nghttp3_conn *h3, int64_t sid, uint64_t app_err, void *ud, void *sud)
{
    (void)h3; (void)sid; (void)app_err; (void)ud;
    conn_t *st = sud;
    if (st && !st->dead) {
        st->h2_detached = 1;   /* QUIC is done with it */
        conn_close(st);
    }
    return 0;
}

static int h3_cb_recv_data(nghttp3_conn *h3, int64_t sid, const uint8_t *data, size_t len, void *ud, void *sud)
{
    (void)h3;
    h3conn_t *c = ud;
    conn_t *st = sud;
    int credit_now = 1;
    if (st && !st->dead && st->state == CS_UPSTREAM && st->body_stream) {
        st->h2_unconsumed += len;   /* credited once forwarded */
        credit_now = 0;
    }
    if (credit_now) {
        ngtcp2_conn_extend_max_stream_offset(c->qc, sid, len);
        ngtcp2_conn_extend_max_offset(c->qc, len);
    }
    if (!st || st->dead)
        return 0;
    if (credit_now && st->state != CS_HEAD && st->state != CS_BODY)
        return 0;   /* the response is already decided: drop the rest */
    if (st->h2_req_raw) {
        buf_append(&st->rbuf, data, len);
    } else {
        buf_printf(&st->rbuf, "%zx\r\n", len);
        buf_append(&st->rbuf, data, len);
        buf_puts(&st->rbuf, "\r\n");
    }
    h3_stream_body_progress(st);
    return 0;
}

static int h3_cb_deferred_consume(nghttp3_conn *h3, int64_t sid, size_t consumed, void *ud, void *sud)
{
    (void)h3; (void)sud;
    h3conn_t *c = ud;
    ngtcp2_conn_extend_max_stream_offset(c->qc, sid, consumed);
    ngtcp2_conn_extend_max_offset(c->qc, consumed);
    return 0;
}

static int h3_cb_begin_headers(nghttp3_conn *h3, int64_t sid, void *ud, void *sud)
{
    (void)sud;
    h3conn_t *c = ud;
    conn_t *st = h3_stream_new(c, sid);
    if (!st)
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    nghttp3_conn_set_stream_user_data(h3, sid, st);
    return 0;
}

static int h3_cb_recv_header(nghttp3_conn *h3, int64_t sid, int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags, void *ud, void *sud)
{
    (void)h3; (void)sid; (void)token; (void)flags; (void)ud;
    conn_t *st = sud;
    if (!st || st->dead)
        return 0;
    nghttp3_vec n = nghttp3_rcbuf_get_buf(name), v = nghttp3_rcbuf_get_buf(value);
    return h3_stream_header(st, n.base, n.len, v.base, v.len) < 0 ? NGHTTP3_ERR_CALLBACK_FAILURE : 0;
}

static int h3_cb_end_headers(nghttp3_conn *h3, int64_t sid, int fin, void *ud, void *sud)
{
    (void)h3; (void)sid; (void)ud;
    conn_t *st = sud;
    if (st && !st->dead)
        h3_stream_dispatch(st, !fin);
    return 0;
}

static int h3_cb_end_stream(nghttp3_conn *h3, int64_t sid, void *ud, void *sud)
{
    (void)h3; (void)sid; (void)ud;
    conn_t *st = sud;
    if (!st || st->dead || !st->h2_body_started || !st->h3_has_body)
        return 0;
    if (!st->h2_req_raw && (st->state == CS_HEAD || st->state == CS_BODY || (st->state == CS_UPSTREAM && st->body_stream)))
        buf_puts(&st->rbuf, "0\r\n\r\n");
    st->rd_eof = 1;
    h3_stream_body_progress(st);
    return 0;
}

static int h3_cb_stop_sending(nghttp3_conn *h3, int64_t sid, uint64_t app_err, void *ud, void *sud)
{
    (void)h3; (void)sud;
    h3conn_t *c = ud;
    ngtcp2_conn_shutdown_stream_read(c->qc, 0, sid, app_err);
    return 0;
}

static int h3_cb_reset_stream(nghttp3_conn *h3, int64_t sid, uint64_t app_err, void *ud, void *sud)
{
    (void)h3; (void)sud;
    h3conn_t *c = ud;
    ngtcp2_conn_shutdown_stream_write(c->qc, 0, sid, app_err);
    return 0;
}

static int h3_http_setup(h3conn_t *c)
{
    if (c->h3)
        return 0;
    nghttp3_callbacks cb;
    memset(&cb, 0, sizeof cb);
    cb.acked_stream_data = h3_cb_acked;
    cb.stream_close = h3_cb_stream_close;
    cb.recv_data = h3_cb_recv_data;
    cb.deferred_consume = h3_cb_deferred_consume;
    cb.begin_headers = h3_cb_begin_headers;
    cb.recv_header = h3_cb_recv_header;
    cb.end_headers = h3_cb_end_headers;
    cb.end_stream = h3_cb_end_stream;
    cb.stop_sending = h3_cb_stop_sending;
    cb.reset_stream = h3_cb_reset_stream;
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams = 100;
    settings.max_field_section_size = HTTP_MAX_HEAD;
    if (nghttp3_conn_server_new(&c->h3, &cb, &settings, NULL, c) != 0)
        return -1;
    nghttp3_conn_set_max_client_streams_bidi(c->h3, H3_MAX_STREAMS);
    int64_t ctrl, qenc, qdec;
    if (ngtcp2_conn_open_uni_stream(c->qc, &ctrl, NULL) != 0 ||
        nghttp3_conn_bind_control_stream(c->h3, ctrl) != 0 ||
        ngtcp2_conn_open_uni_stream(c->qc, &qenc, NULL) != 0 ||
        ngtcp2_conn_open_uni_stream(c->qc, &qdec, NULL) != 0 ||
        nghttp3_conn_bind_qpack_streams(c->h3, qenc, qdec) != 0)
        return -1;
    return 0;
}

/* ---- ngtcp2 callbacks ---- */

static ngtcp2_conn *h3_get_conn(ngtcp2_crypto_conn_ref *ref)
{
    h3conn_t *c = ref->user_data;
    return c->qc;
}

static void h3_cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx)
{
    (void)ctx;
    h3_random(dest, destlen);
}

static int h3_cb_new_cid(ngtcp2_conn *qc, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *ud)
{
    (void)qc;
    h3conn_t *c = ud;
    cid->datalen = cidlen;
    h3_random(cid->data, cidlen);
    h3_random(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return h3_cid_add(c, cid) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int h3_cb_remove_cid(ngtcp2_conn *qc, const ngtcp2_cid *cid, void *ud)
{
    (void)qc;
    h3_cid_del(ud, cid);
    return 0;
}

static int h3_cb_handshake_completed(ngtcp2_conn *qc, void *ud)
{
    (void)qc;
    h3conn_t *c = ud;
    size_t len = sizeof c->sni - 1;
    unsigned type = 0;
    if (gnutls_server_name_get(c->tls, c->sni, &len, &type, 0) == GNUTLS_E_SUCCESS && type == GNUTLS_NAME_DNS)
        c->sni[len] = 0;
    else
        c->sni[0] = 0;
    return h3_http_setup(c) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int h3_cb_recv_stream_data(ngtcp2_conn *qc, uint32_t flags, int64_t sid, uint64_t offset,
                                  const uint8_t *data, size_t datalen, void *ud, void *sud)
{
    (void)offset; (void)sud;
    h3conn_t *c = ud;
    if (!c->h3 && h3_http_setup(c) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    nghttp3_ssize n = nghttp3_conn_read_stream(c->h3, sid, data, datalen, flags & NGTCP2_STREAM_DATA_FLAG_FIN);
    if (n < 0) {
        LOGD("http/3: %s", nghttp3_strerror((int)n));
        ngtcp2_ccerr_set_application_error(&c->err, nghttp3_err_infer_quic_app_error_code((int)n), NULL, 0);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    ngtcp2_conn_extend_max_stream_offset(qc, sid, (uint64_t)n);
    ngtcp2_conn_extend_max_offset(qc, (uint64_t)n);
    return 0;
}

static int h3_cb_acked_offset(ngtcp2_conn *qc, int64_t sid, uint64_t offset, uint64_t datalen, void *ud, void *sud)
{
    (void)qc; (void)offset; (void)sud;
    h3conn_t *c = ud;
    if (c->h3 && nghttp3_conn_add_ack_offset(c->h3, sid, datalen) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static int h3_cb_quic_stream_close(ngtcp2_conn *qc, uint32_t flags, int64_t sid, uint64_t app_err, void *ud, void *sud)
{
    (void)sud;
    h3conn_t *c = ud;
    if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
        app_err = NGHTTP3_H3_NO_ERROR;
    if (c->h3) {
        int rv = nghttp3_conn_close_stream(c->h3, sid, app_err);
        if (rv != 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
            ngtcp2_ccerr_set_application_error(&c->err, nghttp3_err_infer_quic_app_error_code(rv), NULL, 0);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }
    /* ngtcp2 no longer references this stream's data */
    for (h3orphan_t **pp = &c->orphans; *pp; pp = &(*pp)->next)
        if ((*pp)->sid == sid) {
            h3orphan_t *o = *pp;
            *pp = o->next;
            h3_chunks_free(o->chunks);
            free(o);
            break;
        }
    if (ngtcp2_is_bidi_stream(sid))
        ngtcp2_conn_extend_max_streams_bidi(qc, 1);
    return 0;
}

static int h3_cb_stream_reset(ngtcp2_conn *qc, int64_t sid, uint64_t final_size, uint64_t app_err, void *ud, void *sud)
{
    (void)qc; (void)final_size; (void)app_err; (void)sud;
    h3conn_t *c = ud;
    if (c->h3 && nghttp3_conn_shutdown_stream_read(c->h3, sid) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static int h3_cb_stop_sending_q(ngtcp2_conn *qc, int64_t sid, uint64_t app_err, void *ud, void *sud)
{
    (void)qc; (void)app_err; (void)sud;
    h3conn_t *c = ud;
    if (c->h3 && nghttp3_conn_shutdown_stream_read(c->h3, sid) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static int h3_cb_extend_max_remote_bidi(ngtcp2_conn *qc, uint64_t max_streams, void *ud)
{
    (void)qc;
    h3conn_t *c = ud;
    if (c->h3)
        nghttp3_conn_set_max_client_streams_bidi(c->h3, max_streams);
    return 0;
}

static int h3_cb_extend_max_stream_data(ngtcp2_conn *qc, int64_t sid, uint64_t max_data, void *ud, void *sud)
{
    (void)qc; (void)max_data; (void)sud;
    h3conn_t *c = ud;
    if (c->h3 && nghttp3_conn_unblock_stream(c->h3, sid) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

/* ---- connections ---- */

static h3conn_t *h3_conn_new(h3sock_t *hs, const ngtcp2_pkt_hd *hd, const struct sockaddr_storage *local,
                             socklen_t locallen, const struct sockaddr_storage *remote, socklen_t remotelen)
{
    if (!hs->cred || hs->retiring)
        return NULL;
    if (g_cfg->max_connections > 0 && g_stats.active_conns >= g_cfg->max_connections)
        return NULL;
    char ip[64];
    sockaddr_to_str((const struct sockaddr *)remote, ip, sizeof ip, 0);
    int tracked = 0;
    if (g_cfg->ipguard.enabled && g_ipguard) {
        if (ipguard_admit(g_ipguard, &g_cfg->ipguard, ip, g_now) != IPGUARD_OK)
            return NULL;
        tracked = 1;
    }
    h3conn_t *c = xcalloc(1, sizeof *c);
    c->sock = hs;
    c->cred = hs->cred;
    c->cred->refs++;
    /* the config canary applies to QUIC connections as it does to TCP ones */
    c->cfg = g_cfg;
    if (g_canary_old) {
        int pct = (int)sh_get(SH_CANARY);
        if (pct > 0 && (int)(canary_rand() % 100) >= pct && select_server(g_canary_old, hs->addr, NULL))
            c->cfg = g_canary_old;
    }
    config_ref(c->cfg);
    memcpy(&c->local, local, locallen);
    c->locallen = locallen;
    memcpy(&c->remote, remote, remotelen);
    c->remotelen = remotelen;
    snprintf(c->peer_ip, sizeof c->peer_ip, "%s", ip);
    sockaddr_to_str((const struct sockaddr *)remote, c->peer_str, sizeof c->peer_str, 1);
    c->ip_tracked = tracked;
    c->expiry = UINT64_MAX;
    ngtcp2_ccerr_default(&c->err);

    ngtcp2_cid scid;
    scid.datalen = H3_SCID_LEN;
    h3_random(scid.data, scid.datalen);

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = h3_ts();
    settings.max_tx_udp_payload_size = H3_TX_PKT;
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = 1024 * 1024;
    params.initial_max_stream_data_bidi_remote = 1024 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_data = 4 * 1024 * 1024;
    params.initial_max_streams_bidi = H3_MAX_STREAMS;
    params.initial_max_streams_uni = 3;
    params.max_idle_timeout = (ngtcp2_duration)(c->cfg->servers[0]->idle_timeout > 0 ? c->cfg->servers[0]->idle_timeout : 120) * NGTCP2_SECONDS;
    params.active_connection_id_limit = 7;
    params.disable_active_migration = 1;   /* SO_REUSEPORT steers by address: stay on this worker */
    params.original_dcid = hd->dcid;
    params.original_dcid_present = 1;
    params.stateless_reset_token_present = 1;
    h3_random(params.stateless_reset_token, sizeof params.stateless_reset_token);

    ngtcp2_callbacks cb;
    memset(&cb, 0, sizeof cb);
    cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.update_key = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    cb.rand = h3_cb_rand;
    cb.get_new_connection_id = h3_cb_new_cid;
    cb.remove_connection_id = h3_cb_remove_cid;
    cb.handshake_completed = h3_cb_handshake_completed;
    cb.recv_stream_data = h3_cb_recv_stream_data;
    cb.acked_stream_data_offset = h3_cb_acked_offset;
    cb.stream_close = h3_cb_quic_stream_close;
    cb.stream_reset = h3_cb_stream_reset;
    cb.stream_stop_sending = h3_cb_stop_sending_q;
    cb.extend_max_remote_streams_bidi = h3_cb_extend_max_remote_bidi;
    cb.extend_max_stream_data = h3_cb_extend_max_stream_data;

    ngtcp2_path path = {
        { (ngtcp2_sockaddr *)&c->local, c->locallen },
        { (ngtcp2_sockaddr *)&c->remote, c->remotelen },
        NULL,
    };
    if (ngtcp2_conn_server_new(&c->qc, &hd->scid, &scid, &path, hd->version, &cb, &settings, &params, NULL, c) != 0)
        goto fail;
    if (gnutls_init(&c->tls, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET | GNUTLS_NO_END_OF_EARLY_DATA) != 0)
        goto fail;
    if (gnutls_priority_set_direct(c->tls, "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:"
                                   "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305", NULL) != 0 ||
        ngtcp2_crypto_gnutls_configure_server_session(c->tls) != 0 ||
        gnutls_credentials_set(c->tls, GNUTLS_CRD_CERTIFICATE, c->cred->cred) != 0)
        goto fail;
    gnutls_datum_t alpn = { (unsigned char *)"h3", 2 };
    gnutls_alpn_set_protocols(c->tls, &alpn, 1, GNUTLS_ALPN_MANDATORY);
    c->ref.get_conn = h3_get_conn;
    c->ref.user_data = c;
    gnutls_session_set_ptr(c->tls, &c->ref);
    ngtcp2_conn_set_tls_native_handle(c->qc, c->tls);

    h3_cid_add(c, &scid);
    h3_cid_add(c, &hd->dcid);   /* the client may retransmit its Initial to the original DCID */
    c->next = g_h3_conns;
    g_h3_conns = c;
    hs->nconns++;
    g_stats.active_conns++;
    return c;

fail:
    if (c->tls)
        gnutls_deinit(c->tls);
    if (c->qc)
        ngtcp2_conn_del(c->qc);
    h3_cred_unref(c->cred);
    config_unref(c->cfg);
    if (tracked)
        ipguard_release(g_ipguard, ip);
    free(c);
    return NULL;
}

/* Close every stream of a connection that is going away. */
static void h3_conn_detach_streams(h3conn_t *c)
{
    while (c->nstreams > 0) {
        conn_t *st = c->streams[c->nstreams - 1];
        st->h2_detached = 1;   /* QUIC will not touch its bytes again */
        if (st->dead) {
            h3_streams_del(c, st);
            continue;
        }
        conn_close(st);        /* h3_stream_close() unlinks it and frees its chunks */
    }
}

/* Unlink and free a connection; only at the end of an event batch. */
static void h3_conn_free(h3conn_t *c)
{
    for (h3conn_t **pp = &g_h3_conns; *pp; pp = &(*pp)->next)
        if (*pp == c) {
            *pp = c->next;
            break;
        }
    h3_conn_detach_streams(c);
    while (c->ncids > 0)
        h3_cid_del(c, &c->cids[c->ncids - 1]);
    while (c->orphans) {
        h3orphan_t *o = c->orphans;
        c->orphans = o->next;
        h3_chunks_free(o->chunks);
        free(o);
    }
    if (c->h3)
        nghttp3_conn_del(c->h3);
    if (c->qc)
        ngtcp2_conn_del(c->qc);
    if (c->tls)
        gnutls_deinit(c->tls);
    h3_cred_unref(c->cred);
    if (c->ip_tracked && g_ipguard)
        ipguard_release(g_ipguard, c->peer_ip);
    config_unref(c->cfg);
    c->sock->nconns--;
    g_stats.active_conns--;
    free(c->streams);
    free(c);
}

/* Send CONNECTION_CLOSE and enter the closing period. */
static void h3_conn_close(h3conn_t *c)
{
    if (c->closing || c->draining || c->dead)
        return;
    h3_conn_detach_streams(c);
    if (!ngtcp2_conn_in_closing_period(c->qc) && !ngtcp2_conn_in_draining_period(c->qc)) {
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi;
        ngtcp2_ssize n = ngtcp2_conn_write_connection_close(c->qc, &ps.path, &pi, c->closebuf, sizeof c->closebuf,
                                                           &c->err, h3_ts());
        if (n > 0) {
            c->closelen = (size_t)n;
            h3_send(c->sock, &ps.path, c->closebuf, c->closelen);
        }
    }
    c->closing = 1;
    c->close_until = g_now + 3.0 * (double)ngtcp2_conn_get_pto(c->qc) / (double)NGTCP2_SECONDS;
}

static void h3_conn_error(h3conn_t *c, int rv)
{
    if (rv == NGTCP2_ERR_DRAINING) {
        h3_conn_detach_streams(c);
        c->draining = 1;
        c->close_until = g_now + 3.0 * (double)ngtcp2_conn_get_pto(c->qc) / (double)NGTCP2_SECONDS;
        return;
    }
    if (rv == NGTCP2_ERR_DROP_CONN || rv == NGTCP2_ERR_IDLE_CLOSE) {
        c->dead = 1;
        return;
    }
    if (rv == NGTCP2_ERR_CRYPTO)
        ngtcp2_ccerr_set_tls_alert(&c->err, ngtcp2_conn_get_tls_alert(c->qc), NULL, 0);
    else if (c->err.type == NGTCP2_CCERR_TYPE_TRANSPORT && c->err.error_code == 0)
        ngtcp2_ccerr_set_liberr(&c->err, rv, NULL, 0);
    h3_conn_close(c);
}

/* Write whatever ngtcp2 and nghttp3 have to send. */
static void h3_conn_send(h3conn_t *c)
{
    if (c->dead || c->closing || c->draining)
        return;
    c->want_send = 0;
    ngtcp2_tstamp ts = h3_ts();
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi;
    uint8_t out[H3_TX_PKT];
    for (int pkts = 0; pkts < 64;) {
        int64_t sid = -1;
        int fin = 0;
        nghttp3_vec vec[16];
        nghttp3_ssize nvec = 0;
        if (c->h3 && ngtcp2_conn_get_max_data_left(c->qc)) {
            nvec = nghttp3_conn_writev_stream(c->h3, &sid, &fin, vec, 16);
            if (nvec < 0) {
                ngtcp2_ccerr_set_application_error(&c->err, nghttp3_err_infer_quic_app_error_code((int)nvec), NULL, 0);
                h3_conn_close(c);
                return;
            }
        }
        ngtcp2_ssize ndatalen = -1;
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE | (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
        ngtcp2_ssize n = ngtcp2_conn_writev_stream(c->qc, &ps.path, &pi, out, sizeof out, &ndatalen, flags, sid,
                                                   (const ngtcp2_vec *)vec, (size_t)nvec, ts);
        if (n < 0) {
            if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED && c->h3 && sid >= 0) {
                nghttp3_conn_block_stream(c->h3, sid);
                continue;
            }
            if (n == NGTCP2_ERR_STREAM_SHUT_WR && c->h3 && sid >= 0) {
                nghttp3_conn_shutdown_stream_write(c->h3, sid);
                continue;
            }
            if (n == NGTCP2_ERR_WRITE_MORE) {
                if (c->h3 && sid >= 0 && nghttp3_conn_add_write_offset(c->h3, sid, (size_t)ndatalen) != 0) {
                    h3_conn_close(c);
                    return;
                }
                continue;
            }
            h3_conn_error(c, (int)n);
            return;
        }
        if (ndatalen >= 0 && c->h3 && sid >= 0 && nghttp3_conn_add_write_offset(c->h3, sid, (size_t)ndatalen) != 0) {
            h3_conn_close(c);
            return;
        }
        if (n == 0)
            break;
        h3_send(c->sock, &ps.path, out, (size_t)n);
        if (++pkts == 64)
            c->want_send = 1;   /* more to go: come back right after this batch */
    }
    ngtcp2_conn_update_pkt_tx_time(c->qc, ts);
    c->expiry = ngtcp2_conn_get_expiry(c->qc);
    /* streams whose wbuf drained can take more from their source */
    for (int i = 0; i < c->nstreams; i++) {
        conn_t *st = c->streams[i];
        if (st->dead)
            continue;
        if (st->upstream_paused && st->uc && buf_readable(&st->wbuf) < WBUF_LOW_WATER)
            conn_resume_upstream(st);
        if (st->file_fd >= 0 && buf_readable(&st->wbuf) < WBUF_LOW_WATER)
            file_pump(st);
    }
}

static void h3_send_version_negotiation(h3sock_t *hs, const ngtcp2_version_cid *vc, const ngtcp2_path *path)
{
    uint8_t out[1280];
    uint32_t sv[] = { NGTCP2_PROTO_VER_V1 };
    uint8_t r;
    h3_random(&r, 1);
    ngtcp2_ssize n = ngtcp2_pkt_write_version_negotiation(out, sizeof out, r, vc->scid, vc->scidlen,
                                                          vc->dcid, vc->dcidlen, sv, 1);
    if (n > 0)
        h3_send(hs, path, out, (size_t)n);
}

static void h3_on_packet(h3sock_t *hs, const uint8_t *pkt, size_t len, struct sockaddr_storage *local,
                         socklen_t locallen, struct sockaddr_storage *remote, socklen_t remotelen)
{
    ngtcp2_path path = {
        { (ngtcp2_sockaddr *)local, locallen },
        { (ngtcp2_sockaddr *)remote, remotelen },
        NULL,
    };
    ngtcp2_version_cid vc;
    int rv = ngtcp2_pkt_decode_version_cid(&vc, pkt, len, H3_SCID_LEN);
    if (rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
        h3_send_version_negotiation(hs, &vc, &path);
        return;
    }
    if (rv != 0)
        return;
    h3conn_t *c = h3_cid_find(vc.dcid, vc.dcidlen);
    if (!c) {
        ngtcp2_pkt_hd hd;
        if (g_shutting_down || ngtcp2_accept(&hd, pkt, len) != 0)
            return;   /* not an Initial for a new connection */
        c = h3_conn_new(hs, &hd, local, locallen, remote, remotelen);
        if (!c)
            return;
    }
    if (c->dead || c->draining)
        return;
    if (c->closing) {
        if (c->closelen)
            h3_send(c->sock, &path, c->closebuf, c->closelen);
        return;
    }
    ngtcp2_pkt_info pi;
    memset(&pi, 0, sizeof pi);
    rv = ngtcp2_conn_read_pkt(c->qc, &path, &pi, pkt, len, h3_ts());
    if (rv != 0) {
        h3_conn_error(c, rv);
        return;
    }
    h3_conn_send(c);
}

static void h3_sock_cb(ev_t *e, uint32_t events)
{
    (void)events;
    h3sock_t *hs = (h3sock_t *)e;
    for (int k = 0; k < 64; k++) {
        struct sockaddr_storage remote;
        struct iovec iov = { g_h3_rx, sizeof g_h3_rx };
        union {
            struct cmsghdr h;
            uint8_t b[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(struct in_pktinfo))];
        } ctl;
        struct msghdr mh;
        memset(&mh, 0, sizeof mh);
        mh.msg_name = &remote;
        mh.msg_namelen = sizeof remote;
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = &ctl;
        mh.msg_controllen = sizeof ctl;
        ssize_t n = recvmsg(hs->ev.fd, &mh, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        struct sockaddr_storage local;
        memcpy(&local, &hs->bound, hs->boundlen);
        socklen_t locallen = hs->boundlen;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
            if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_PKTINFO && local.ss_family == AF_INET6) {
                struct in6_pktinfo pinfo;
                memcpy(&pinfo, CMSG_DATA(cm), sizeof pinfo);
                ((struct sockaddr_in6 *)&local)->sin6_addr = pinfo.ipi6_addr;
            } else if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO && local.ss_family == AF_INET) {
                struct in_pktinfo pinfo;
                memcpy(&pinfo, CMSG_DATA(cm), sizeof pinfo);
                ((struct sockaddr_in *)&local)->sin_addr = pinfo.ipi_addr;
            }
        }
        h3_on_packet(hs, g_h3_rx, (size_t)n, &local, locallen, &remote, mh.msg_namelen);
    }
}

/* ---- event-loop hooks ---- */

/* epoll_wait timeout: no later than the nearest QUIC timer. */
static int h3_poll_timeout(int def_ms)
{
    if (!g_h3_conns)
        return def_ms;
    ngtcp2_tstamp now = h3_ts();
    int best = def_ms;
    for (h3conn_t *c = g_h3_conns; c; c = c->next) {
        if (c->dead || c->want_send)
            return 0;
        if (c->closing || c->draining) {
            int ms = (int)((c->close_until - now_mono()) * 1000) + 1;
            if (ms < best)
                best = ms < 0 ? 0 : ms;
            continue;
        }
        if (c->expiry == UINT64_MAX)
            continue;
        if (c->expiry <= now)
            return 0;
        uint64_t ms = (c->expiry - now + 999999) / 1000000;
        if (ms < (uint64_t)best)
            best = (int)ms;
    }
    return best;
}

/* After each event batch: fire QUIC timers, send what is pending, and free
 * finished connections and retired sockets. */
static void h3_after_batch(void)
{
    ngtcp2_tstamp now = h3_ts();
    for (h3conn_t *c = g_h3_conns; c; c = c->next) {
        if (c->dead)
            continue;
        if (c->closing || c->draining) {
            if (g_now >= c->close_until)
                c->dead = 1;
            continue;
        }
        if (c->expiry <= now) {
            int rv = ngtcp2_conn_handle_expiry(c->qc, now);
            if (rv != 0) {
                h3_conn_error(c, rv);
                continue;
            }
            c->want_send = 1;
        }
        if (g_shutting_down && c->nstreams == 0) {
            ngtcp2_ccerr_set_application_error(&c->err, NGHTTP3_H3_NO_ERROR, NULL, 0);
            h3_conn_close(c);
            continue;
        }
        if (c->want_send)
            h3_conn_send(c);
    }
    for (h3conn_t *c = g_h3_conns, *next; c; c = next) {
        next = c->next;
        if (c->dead)
            h3_conn_free(c);
    }
    for (h3sock_t **pp = &g_h3_socks; *pp;) {
        h3sock_t *hs = *pp;
        if (hs->retiring && hs->nconns == 0) {
            *pp = hs->next;
            LOGI("http/3: stopped listening on %s (udp)", hs->addr);
            ev_retire(&hs->ev);
            continue;
        }
        pp = &hs->next;
    }
}

/* Graceful shutdown: tell clients to go away and accept no new connections. */
static void h3_shutdown(void)
{
    for (h3sock_t *hs = g_h3_socks; hs; hs = hs->next)
        hs->retiring = 1;
    g_h3_live = 0;
    for (h3conn_t *c = g_h3_conns; c; c = c->next)
        if (!c->dead && !c->closing && !c->draining && c->h3 && !c->goaway) {
            nghttp3_conn_shutdown(c->h3);
            c->goaway = 1;
            c->want_send = 1;
        }
}

static void h3_teardown(void)
{
    while (g_h3_conns)
        h3_conn_free(g_h3_conns);
    while (g_h3_socks) {
        h3sock_t *hs = g_h3_socks;
        g_h3_socks = hs->next;
        ev_retire(&hs->ev);
    }
}
