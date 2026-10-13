/*
 * proxy.c - epoll event loop, client/upstream connection state machines,
 * active health checks, the admin API and config reloading.
 *
 * Every socket is non-blocking and registered with a level-triggered epoll
 * instance. Each registered object embeds an ev_t as its first member so the
 * callback can recover the object from the epoll data pointer.
 */
#include "limer.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef LIMER_TLS
#include <openssl/err.h>
#endif

#define READ_CHUNK       (16 * 1024)
#define WBUF_HIGH_WATER  (1024 * 1024)   /* pause upstream reads above this */
#define WBUF_LOW_WATER   (64 * 1024)     /* resume below this               */
#define RBUF_PIPELINE_CAP (64 * 1024)    /* stop reading pipelined data     */
#define TICK_MS          250

typedef struct ev {
    int fd;
    uint32_t mask;
    void (*cb)(struct ev *, uint32_t);
    void (*destroy)(struct ev *);   /* called when the graveyard is reaped */
    struct ev *gnext;
} ev_t;

/* ------------------------------------------------------------------ */
/* Global state                                                        */
/* ------------------------------------------------------------------ */

static int g_epfd = -1;
static config_t *g_cfg;
static int g_worker_id;
static double g_now;
static volatile sig_atomic_t g_reload_flag;
static volatile sig_atomic_t g_shutdown_flag;
static int g_shutting_down;
static double g_shutdown_deadline;

static struct {
    uint64_t requests;
    uint64_t resp_class[6];     /* index 1..5 */
    uint64_t upstream_errors;
    uint64_t retries;
    int active_conns;
    int active_uconns;
} g_stats;

/* ------------------------------------------------------------------ */
/* epoll helpers                                                       */
/* ------------------------------------------------------------------ */

static int ev_add(ev_t *e, uint32_t mask)
{
    struct epoll_event ee;
    memset(&ee, 0, sizeof ee);
    ee.events = mask;
    ee.data.ptr = e;
    e->mask = mask;
    return epoll_ctl(g_epfd, EPOLL_CTL_ADD, e->fd, &ee);
}

static int ev_mod(ev_t *e, uint32_t mask)
{
    if (e->mask == mask)
        return 0;
    struct epoll_event ee;
    memset(&ee, 0, sizeof ee);
    ee.events = mask;
    ee.data.ptr = e;
    e->mask = mask;
    return epoll_ctl(g_epfd, EPOLL_CTL_MOD, e->fd, &ee);
}

static void ev_del(ev_t *e)
{
    if (e->fd >= 0)
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, e->fd, NULL);
}

/* ------------------------------------------------------------------ */
/* Object types                                                        */
/* ------------------------------------------------------------------ */

typedef struct listener {
    ev_t ev;
    config_t *cfg;
    char *addr;
    server_t **servers;     /* sites sharing this bind address */
    int nservers;
    server_t *default_srv;  /* catch-all site, or the first one */
    int tls;
    double paused_until;    /* accept() backs off after EMFILE/ENFILE */
    struct listener *next;
} listener_t;

enum conn_state {
    CS_HEAD = 0,     /* reading request head                   */
    CS_BODY,         /* reading request body                   */
    CS_UPSTREAM,     /* request handed to an upstream          */
    CS_LOCAL,        /* locally generated response in wbuf     */
    CS_TUNNEL,       /* bidirectional copy after 101           */
    CS_CLOSING,      /* flushing wbuf, then close              */
};

enum resp_mode {
    RM_NONE = 0,     /* no response body                       */
    RM_LENGTH,       /* Content-Length delimited               */
    RM_CHUNKED,      /* chunked passthrough                    */
    RM_DECHUNK,      /* chunked upstream -> close-delimited    */
    RM_CLOSE,        /* until upstream closes                  */
};

enum uconn_state { US_CONNECTING = 0, US_ACTIVE, US_IDLE, US_TUNNEL };

struct conn;

typedef struct uconn {
    ev_t ev;
    upstream_t *up;
    pool_t *pool;
    config_t *cfg;
    struct conn *c;
    int state;
    buf_t rbuf, wbuf;
    http_resp_t resp;
    int head_done;
    int got_bytes;
    int reused;
    int connected;
    double idle_since;
    struct uconn *idle_next;
    struct uconn *prev, *next;      /* global list */
    int dead;
} uconn_t;

typedef struct conn {
    ev_t ev;
    server_t *srv;
    config_t *cfg;
    char listen_addr[128];
    struct sockaddr_storage peer;
    socklen_t peerlen;
    char peer_ip[64];
    char peer_str[80];
    struct conn *prev, *next;
#ifdef LIMER_TLS
    SSL *ssl;
    int tls_handshaking;
#endif
    int state;
    buf_t rbuf, wbuf;
    http_req_t req;
    req_ctx_t ctx;
    double deadline;
    int rd_eof;
    int close_after_write;
    int got_request_bytes;
    uint64_t requests;

    /* current request */
    route_t *route;
    pool_t *pool;
    upstream_t *up;
    uint64_t tried;
    int attempts;
    uconn_t *uc;
    double req_start;
    int resp_status;
    uint64_t resp_bytes;
    int resp_head_sent;
    int resp_mode;
    int64_t resp_remaining;
    chunk_state_t resp_cs;
    int upstream_paused;
    int expect_sent;
    int upstream_reusable;      /* response framing allows pooling the upstream conn */
    int resp_committed;         /* some response bytes reached the socket */
    size_t resp_head_mark;      /* wbuf readable length before the response head */
    int pre_head_close;         /* close_after_write before the head was built */
    encoder_t *enc;             /* response compressor, when active */
    buf_t enc_out;              /* scratch for encoder output */
    buf_t dechunk;              /* scratch for de-chunked upstream bodies */
    int out_chunked;            /* we frame the body as chunked ourselves */
    int body_sync;              /* flush the encoder after every piece (streaming) */
    int file_fd;                /* static file being streamed, or -1 */
    off_t file_off;
    off_t file_remaining;
    char lb_why[128];
    int in_process;
    int dead;
} conn_t;

typedef struct hc_conn {
    ev_t ev;
    upstream_t *up;
    pool_t *pool;
    config_t *cfg;
    buf_t rbuf, wbuf;
    int connected;
    double deadline;
} hc_conn_t;

static listener_t *g_listeners;
static conn_t *g_conns;
static uconn_t *g_uconns;
static ev_t *g_graveyard;
static ev_t g_timer_ev;

/*
 * Closed objects are unlinked and their sockets closed immediately, but the
 * memory is released only after the current batch of events has been
 * handled. That lets callbacks safely test `->dead` after calling anything
 * that might have closed the object, and keeps epoll event pointers valid
 * for the rest of the batch.
 */
static void ev_retire(ev_t *e)
{
    ev_del(e);
    if (e->fd >= 0)
        close(e->fd);
    e->fd = -1;
    e->gnext = g_graveyard;
    g_graveyard = e;
}

static void reap_graveyard(void)
{
    while (g_graveyard) {
        ev_t *e = g_graveyard;
        g_graveyard = e->gnext;
        e->destroy(e);
    }
}

static void conn_close(conn_t *c);
static void conn_process(conn_t *c);
static void conn_flush(conn_t *c);
static void conn_try_upstream(conn_t *c);
static void conn_send_error(conn_t *c, int status, const char *msg, int close);
static void uconn_close(uconn_t *uc);
static void uconn_cb(ev_t *e, uint32_t events);
static void hc_cb(ev_t *e, uint32_t events);
static void hc_close(hc_conn_t *h);
static void admin_handle(conn_t *c);
static void conn_update_mask(conn_t *c);

/* ------------------------------------------------------------------ */
/* Socket I/O with optional TLS                                        */
/* ------------------------------------------------------------------ */

/* returns bytes read (>0), 0 on EOF, -1 would block, -2 error */
static ssize_t conn_read_raw(conn_t *c, char *buf, size_t n)
{
#ifdef LIMER_TLS
    if (c->ssl) {
        ERR_clear_error();
        int r = SSL_read(c->ssl, buf, (int)(n > INT32_MAX ? INT32_MAX : n));
        if (r > 0)
            return r;
        int e = SSL_get_error(c->ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
            return -1;
        if (e == SSL_ERROR_ZERO_RETURN)
            return 0;
        if (e == SSL_ERROR_SYSCALL && r == 0)
            return 0; /* unclean EOF */
        return -2;
    }
#endif
    ssize_t r = read(c->ev.fd, buf, n);
    if (r > 0)
        return r;
    if (r == 0)
        return 0;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return -1;
    return -2;
}

/* returns bytes written (>0), -1 would block, -2 error */
static ssize_t conn_write_raw(conn_t *c, const char *buf, size_t n)
{
#ifdef LIMER_TLS
    if (c->ssl) {
        ERR_clear_error();
        int r = SSL_write(c->ssl, buf, (int)(n > INT32_MAX ? INT32_MAX : n));
        if (r > 0)
            return r;
        int e = SSL_get_error(c->ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
            return -1;
        return -2;
    }
#endif
    ssize_t r = write(c->ev.fd, buf, n);
    if (r >= 0)
        return r;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return -1;
    return -2;
}

static ssize_t fd_read(int fd, buf_t *b)
{
    if (buf_reserve(b, READ_CHUNK) < 0)
        return -2;
    ssize_t r = read(fd, buf_wptr(b), buf_wavail(b));
    if (r > 0) {
        buf_commit(b, (size_t)r);
        return r;
    }
    if (r == 0)
        return 0;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return -1;
    return -2;
}

/* flush a buffer to a plain fd: returns 1 drained, 0 would block, -1 error */
static int fd_flush(int fd, buf_t *b)
{
    while (buf_readable(b) > 0) {
        ssize_t r = write(fd, buf_rptr(b), buf_readable(b));
        if (r > 0) {
            buf_consume(b, (size_t)r);
            continue;
        }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            return 0;
        return -1;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Placeholders                                                        */
/* ------------------------------------------------------------------ */

static void expand_placeholders(const char *v, conn_t *c, buf_t *out)
{
    const char *p = v;
    while (*p) {
        if (*p != '{') {
            buf_append(out, p, 1);
            p++;
            continue;
        }
        const char *end = strchr(p, '}');
        if (!end) {
            buf_puts(out, p);
            return;
        }
        size_t n = (size_t)(end - p - 1);
        const char *name = p + 1;
#define IS(x) (n == strlen(x) && memcmp(name, x, n) == 0)
        if (IS("remote_ip") || IS("remote")) {
            buf_puts(out, c->peer_ip);
        } else if (IS("remote_port")) {
            const char *colon = strrchr(c->peer_str, ':');
            buf_puts(out, colon ? colon + 1 : "");
        } else if (IS("host")) {
            const char *h = http_hdr_get(c->req.hdrs, c->req.nhdr, "Host");
            buf_puts(out, h ? h : "");
        } else if (IS("upstream_hostport") || IS("upstream")) {
            buf_puts(out, c->up ? c->up->hostport : "");
        } else if (IS("upstream_host")) {
            buf_puts(out, c->up ? c->up->host : "");
        } else if (IS("path")) {
            buf_puts(out, c->req.path ? c->req.path : "");
        } else if (IS("uri")) {
            buf_puts(out, c->req.uri ? c->req.uri : "");
        } else if (IS("query")) {
            buf_puts(out, c->req.query ? c->req.query : "");
        } else if (IS("method")) {
            buf_puts(out, c->req.method ? c->req.method : "");
        } else if (IS("scheme")) {
            buf_puts(out, c->ctx.tls ? "https" : "http");
        } else if (IS("route")) {
            buf_puts(out, c->route ? c->route->name : "");
        } else if (n > 7 && memcmp(name, "header.", 7) == 0) {
            char hn[128];
            snprintf(hn, sizeof hn, "%.*s", (int)(n - 7), name + 7);
            const char *h = http_hdr_get(c->req.hdrs, c->req.nhdr, hn);
            buf_puts(out, h ? h : "");
        } else {
            buf_append(out, p, n + 2);
        }
#undef IS
        p = end + 1;
    }
}

/* Apply header ops to a header list being built. `names`/`values` are the
 * headers collected so far (parallel arrays of buf_t slices). Simpler: we
 * materialize into a small dynamic list. */
typedef struct hlist {
    char **name;
    char **value;
    int n, cap;
} hlist_t;

static void hlist_add(hlist_t *h, const char *name, const char *value)
{
    if (h->n == h->cap) {
        h->cap = h->cap ? h->cap * 2 : 32;
        h->name = xrealloc(h->name, sizeof(char *) * (size_t)h->cap);
        h->value = xrealloc(h->value, sizeof(char *) * (size_t)h->cap);
    }
    h->name[h->n] = xstrdup(name);
    h->value[h->n] = xstrdup(value);
    h->n++;
}

static void hlist_del(hlist_t *h, const char *name)
{
    int w = 0;
    for (int i = 0; i < h->n; i++) {
        if (strcasecmp(h->name[i], name) == 0) {
            free(h->name[i]);
            free(h->value[i]);
        } else {
            h->name[w] = h->name[i];
            h->value[w] = h->value[i];
            w++;
        }
    }
    h->n = w;
}

static void hlist_free(hlist_t *h)
{
    for (int i = 0; i < h->n; i++) {
        free(h->name[i]);
        free(h->value[i]);
    }
    free(h->name);
    free(h->value);
    memset(h, 0, sizeof *h);
}

static void hlist_apply_ops(hlist_t *h, hdr_op_t *ops, int nops, conn_t *c)
{
    buf_t v;
    buf_init(&v);
    for (int i = 0; i < nops; i++) {
        if (ops[i].kind == 2) {
            hlist_del(h, ops[i].name);
            continue;
        }
        buf_reset(&v);
        expand_placeholders(ops[i].value, c, &v);
        buf_append(&v, "", 1);
        if (ops[i].kind == 0)
            hlist_del(h, ops[i].name);
        hlist_add(h, ops[i].name, buf_rptr(&v));
    }
    buf_free(&v);
}

static void hlist_write(hlist_t *h, buf_t *out)
{
    for (int i = 0; i < h->n; i++) {
        buf_puts(out, h->name[i]);
        buf_puts(out, ": ");
        buf_puts(out, h->value[i]);
        buf_puts(out, "\r\n");
    }
}

/* ------------------------------------------------------------------ */
/* Site selection                                                      */
/* ------------------------------------------------------------------ */

static int server_has_bind(const server_t *s, const char *bind)
{
    for (int i = 0; i < s->naddr; i++)
        if (strcmp(s->addrs[i], bind) == 0)
            return 1;
    return 0;
}

/* Pick the site for a Host (without port) on a bind address: exact match,
 * then wildcard match, then the catch-all site. NULL when nothing fits. */
static server_t *select_server(config_t *cfg, const char *bind, const char *host)
{
    server_t *exact = NULL, *wild = NULL, *any = NULL;
    for (int i = 0; i < cfg->nservers; i++) {
        server_t *s = cfg->servers[i];
        if (!server_has_bind(s, bind))
            continue;
        if (s->nhosts == 0) {
            if (!any)
                any = s;
            continue;
        }
        if (!host)
            continue;
        for (int h = 0; h < s->nhosts; h++) {
            if (strcasecmp(s->hosts[h], host) == 0) {
                if (!exact)
                    exact = s;
            } else if (strchr(s->hosts[h], '*')) {
                /* case-insensitive glob */
                char lp[256], lh[256];
                snprintf(lp, sizeof lp, "%s", s->hosts[h]);
                snprintf(lh, sizeof lh, "%s", host);
                for (char *q = lp; *q; q++) *q = (char)tolower((unsigned char)*q);
                for (char *q = lh; *q; q++) *q = (char)tolower((unsigned char)*q);
                if (glob_match(lp, lh) && !wild)
                    wild = s;
            }
        }
    }
    return exact ? exact : wild ? wild : any;
}

/* Host header without the port */
static void host_only(const char *hdr, char *out, size_t n)
{
    if (!hdr) {
        out[0] = 0;
        return;
    }
    snprintf(out, n, "%s", hdr);
    char *rb = strchr(out, ']');
    char *colon = strrchr(rb ? rb : out, ':');
    if (colon)
        *colon = 0;
    size_t l = strlen(out);
    while (l && out[l - 1] == '.')
        out[--l] = 0;
}

#ifdef LIMER_TLS
static SSL_CTX *sni_resolve(SSL *ssl, const char *name)
{
    conn_t *c = SSL_get_app_data(ssl);
    if (!c)
        return NULL;
    server_t *s = select_server(c->cfg, c->listen_addr, name);
    if (!s || !s->ssl_ctx)
        return NULL;
    c->srv = s;
    return s->ssl_ctx;
}
#endif

/* ------------------------------------------------------------------ */
/* Client connections                                                  */
/* ------------------------------------------------------------------ */

static void conn_list_add(conn_t *c)
{
    c->next = g_conns;
    c->prev = NULL;
    if (g_conns)
        g_conns->prev = c;
    g_conns = c;
}

static void conn_list_del(conn_t *c)
{
    if (c->prev)
        c->prev->next = c->next;
    else
        g_conns = c->next;
    if (c->next)
        c->next->prev = c->prev;
}

static void conn_reset_request(conn_t *c)
{
    http_req_free(&c->req);
    http_req_init(&c->req);
    /* idle keep-alive connections should not pin read buffers */
    if (buf_readable(&c->rbuf) == 0)
        buf_free(&c->rbuf);
    c->route = NULL;
    c->pool = NULL;
    c->up = NULL;
    c->tried = 0;
    c->attempts = 0;
    c->uc = NULL;
    c->resp_status = 0;
    c->resp_bytes = 0;
    c->resp_head_sent = 0;
    c->resp_mode = RM_NONE;
    c->resp_remaining = 0;
    memset(&c->resp_cs, 0, sizeof c->resp_cs);
    c->upstream_paused = 0;
    c->expect_sent = 0;
    c->upstream_reusable = 0;
    c->resp_committed = 0;
    c->resp_head_mark = 0;
    c->pre_head_close = 0;
    if (c->enc) {
        encoder_free(c->enc);
        c->enc = NULL;
    }
    buf_reset(&c->enc_out);
    buf_reset(&c->dechunk);
    c->out_chunked = 0;
    c->body_sync = 0;
    if (c->file_fd >= 0) {
        close(c->file_fd);
        c->file_fd = -1;
    }
    c->file_off = c->file_remaining = 0;
    c->lb_why[0] = 0;
    c->got_request_bytes = 0;
}

/* Compute the epoll interest set from the connection's state. */
static void conn_update_mask(conn_t *c)
{
    uint32_t m = 0;
#ifdef LIMER_TLS
    if (c->tls_handshaking) {
        /* mask set by the handshake code */
        return;
    }
#endif
    if (buf_readable(&c->wbuf) > 0)
        m |= EPOLLOUT;
    switch (c->state) {
    case CS_HEAD:
    case CS_BODY:
        if (!c->rd_eof)
            m |= EPOLLIN;
        break;
    case CS_UPSTREAM:
        /* keep watching for pipelined data / disconnect, with a cap */
        if (!c->rd_eof && buf_readable(&c->rbuf) < RBUF_PIPELINE_CAP)
            m |= EPOLLIN;
        break;
    case CS_TUNNEL:
        if (!c->rd_eof && c->uc && buf_readable(&c->uc->wbuf) < WBUF_HIGH_WATER)
            m |= EPOLLIN;
        break;
    case CS_LOCAL:
    case CS_CLOSING:
        break;
    }
    if (m == 0)
        m = EPOLLRDHUP; /* still get notified of errors */
    ev_mod(&c->ev, m);
}

static void conn_log_access(conn_t *c)
{
    server_t *srv = c->srv;
    if (!srv || !srv->access_log || srv->log_fd < 0 || !c->req.method)
        return;
    double ms = (g_now - c->req_start) * 1000.0;
    buf_t b;
    buf_init(&b);
    const char *host = http_hdr_get(c->req.hdrs, c->req.nhdr, "Host");
    if (srv->log_json) {
        buf_printf(&b, "{\"ts\":%.3f,\"remote\":", now_wall());
        log_json_escape(&b, c->peer_str);
        buf_puts(&b, ",\"host\":");
        log_json_escape(&b, host ? host : "");
        buf_puts(&b, ",\"method\":");
        log_json_escape(&b, c->req.method);
        buf_puts(&b, ",\"uri\":");
        log_json_escape(&b, c->req.uri);
        buf_printf(&b, ",\"proto\":\"HTTP/1.%d\",\"tls\":%s,\"status\":%d,\"bytes\":%llu,\"duration_ms\":%.3f,\"route\":",
                   c->req.minor, c->ctx.tls ? "true" : "false", c->resp_status, (unsigned long long)c->resp_bytes, ms);
        log_json_escape(&b, c->route ? c->route->name : "");
        buf_puts(&b, ",\"upstream\":");
        log_json_escape(&b, c->up ? c->up->hostport : "");
        if (c->lb_why[0]) {
            buf_puts(&b, ",\"lb\":");
            log_json_escape(&b, c->lb_why);
        }
        const char *ua = http_hdr_get(c->req.hdrs, c->req.nhdr, "User-Agent");
        if (ua) {
            buf_puts(&b, ",\"user_agent\":");
            log_json_escape(&b, ua);
        }
        buf_puts(&b, "}");
    } else {
        buf_printf(&b, "%s %s \"%s %s HTTP/1.%d\" %d %llu %.1fms route=%s upstream=%s%s%s",
                   c->peer_str, host ? host : "-", c->req.method, c->req.uri, c->req.minor, c->resp_status,
                   (unsigned long long)c->resp_bytes, ms,
                   c->route ? c->route->name : "-",
                   c->up ? c->up->hostport : "-",
                   c->lb_why[0] ? " via=" : "", c->lb_why);
    }
    log_access_to(srv->log_fd, b.data, b.len);
    buf_free(&b);
}

static void conn_destroy(ev_t *e)
{
    conn_t *c = (conn_t *)e;
    if (c->enc)
        encoder_free(c->enc);
    buf_free(&c->enc_out);
    buf_free(&c->dechunk);
    if (c->file_fd >= 0)
        close(c->file_fd);
    buf_free(&c->rbuf);
    buf_free(&c->wbuf);
    http_req_free(&c->req);
    config_unref(c->cfg);
    free(c);
}

static void conn_close(conn_t *c)
{
    if (c->dead)
        return;
    c->dead = 1;
    if (c->uc) {
        uconn_t *uc = c->uc;
        c->uc = NULL;
        uc->c = NULL;
        if (c->up) {
            c->up->active--;
            c->up = NULL;
        }
        uconn_close(uc);
    } else if (c->up) {
        c->up->active--;
        c->up = NULL;
    }
#ifdef LIMER_TLS
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
#endif
    conn_list_del(c);
    g_stats.active_conns--;
    ev_retire(&c->ev);
}

/* Begin closing: flush remaining output first. */
static void conn_finish(conn_t *c)
{
    c->close_after_write = 1;
    c->state = CS_CLOSING;
    if (buf_readable(&c->wbuf) == 0) {
        conn_close(c);
        return;
    }
    conn_flush(c);
}

static void conn_flush(conn_t *c)
{
    while (buf_readable(&c->wbuf) > 0) {
        ssize_t r = conn_write_raw(c, buf_rptr(&c->wbuf), buf_readable(&c->wbuf));
        if (r > 0) {
            buf_consume(&c->wbuf, (size_t)r);
            if (c->resp_head_sent)
                c->resp_committed = 1;
            continue;
        }
        if (r == -1)
            break;
        conn_close(c);
        return;
    }
    if (buf_readable(&c->wbuf) == 0 && c->state == CS_CLOSING) {
        conn_close(c);
        return;
    }
    if (buf_readable(&c->wbuf) == 0 && c->state == CS_HEAD && c->wbuf.cap > 4096)
        buf_free(&c->wbuf);
    if (c->upstream_paused && c->uc && buf_readable(&c->wbuf) < WBUF_LOW_WATER) {
        c->upstream_paused = 0;
        ev_mod(&c->uc->ev, EPOLLIN | (buf_readable(&c->uc->wbuf) ? EPOLLOUT : 0));
    }
    conn_update_mask(c);
}

/* ---- response body pipeline: optional compression + our own chunking ---- */

static void conn_body_write_raw(conn_t *c, const void *d, size_t n)
{
    if (n == 0)
        return;
    if (c->out_chunked) {
        buf_printf(&c->wbuf, "%zx\r\n", n);
        buf_append(&c->wbuf, d, n);
        buf_puts(&c->wbuf, "\r\n");
        c->resp_bytes += n;
    } else {
        buf_append(&c->wbuf, d, n);
        c->resp_bytes += n;
    }
}

/* flush: 0 buffer, 1 sync flush (streaming), 2 finish */
static void conn_body_emit(conn_t *c, const void *d, size_t n, int flush)
{
    if (!c->enc) {
        conn_body_write_raw(c, d, n);
        return;
    }
    buf_reset(&c->enc_out);
    if (encoder_write(c->enc, d, n, &c->enc_out, flush) < 0) {
        LOGW("compression failed; closing connection");
        c->close_after_write = 1;
        return;
    }
    conn_body_write_raw(c, buf_rptr(&c->enc_out), buf_readable(&c->enc_out));
    buf_reset(&c->enc_out);
}

static void conn_body_finish(conn_t *c)
{
    if (c->enc) {
        conn_body_emit(c, "", 0, 2);
        encoder_free(c->enc);
        c->enc = NULL;
    }
    if (c->out_chunked) {
        buf_puts(&c->wbuf, "0\r\n\r\n");
        c->out_chunked = 0;
    }
}

/* Decide whether (and how) to compress a response. Returns the encoding name. */
static const char *conn_pick_encoding(conn_t *c, const char *content_type, int64_t length, int status, const char *existing_encoding)
{
    server_t *s = c->srv;
    if (!s || !s->encode || !encode_available())
        return NULL;
    if (existing_encoding && *existing_encoding && strcasecmp(existing_encoding, "identity") != 0)
        return NULL;
    if (status < 200 || status == 204 || status == 206 || status == 304 || status >= 300)
        return NULL;
    if (c->req.method && strcmp(c->req.method, "HEAD") == 0)
        return NULL;
    if (!encode_compressible(content_type))
        return NULL;
    if (length >= 0 && length < s->encode_min)
        return NULL;
    return encode_choose(s->encode, http_hdr_get(c->req.hdrs, c->req.nhdr, "Accept-Encoding"));
}

static const char *content_type_for(const char *body)
{
    if (!body || !*body)
        return "text/plain; charset=utf-8";
    while (*body == ' ' || *body == '\n' || *body == '\t' || *body == '\r')
        body++;
    if (*body == '{' || *body == '[')
        return "application/json";
    if (*body == '<')
        return "text/html; charset=utf-8";
    return "text/plain; charset=utf-8";
}

static void conn_write_simple_response(conn_t *c, int status, const char *ctype, const char *body, size_t blen,
                                       hdr_op_t *ops, int nops, const char *extra_hdr)
{
    int keep = c->req.keep_alive && !c->close_after_write && !g_shutting_down && c->state != CS_CLOSING;
    hlist_t h = { 0 };
    char tmp[64];
    buf_t packed;
    buf_init(&packed);
    const char *encname = conn_pick_encoding(c, ctype, (int64_t)blen, status, NULL);
    if (encname) {
        encoder_t *e = encoder_new(encname);
        if (e && encoder_write(e, body, blen, &packed, 2) == 0) {
            body = buf_rptr(&packed);
            blen = buf_readable(&packed);
            hlist_add(&h, "Content-Encoding", encname);
            hlist_add(&h, "Vary", "Accept-Encoding");
        }
        encoder_free(e);
    }
    if (ctype)
        hlist_add(&h, "Content-Type", ctype);
    snprintf(tmp, sizeof tmp, "%zu", blen);
    hlist_add(&h, "Content-Length", tmp);
    hlist_add(&h, "Connection", keep ? "keep-alive" : "close");
    hlist_add(&h, "Server", "limer");
    if (c->srv && c->srv->n_hdr_down)
        hlist_apply_ops(&h, c->srv->hdr_down, c->srv->n_hdr_down, c);
    if (ops)
        hlist_apply_ops(&h, ops, nops, c);
    buf_printf(&c->wbuf, "HTTP/1.1 %d %s\r\n", status, http_status_reason(status));
    hlist_write(&h, &c->wbuf);
    if (extra_hdr)
        buf_puts(&c->wbuf, extra_hdr);
    buf_puts(&c->wbuf, "\r\n");
    int is_head = c->req.method && strcmp(c->req.method, "HEAD") == 0;
    if (!is_head && blen)
        buf_append(&c->wbuf, body, blen);
    hlist_free(&h);
    buf_free(&packed);
    c->resp_status = status;
    c->resp_bytes = is_head ? 0 : blen;
    c->resp_head_sent = 1;
    if (!keep)
        c->close_after_write = 1;
}

/* Finish the current request/response cycle and prepare for the next one. */
static void conn_next_request(conn_t *c)
{
    conn_log_access(c);
    c->requests++;
    if (c->resp_status >= 100 && c->resp_status < 600)
        g_stats.resp_class[c->resp_status / 100]++;
    if (c->close_after_write) {
        conn_finish(c);
        return;
    }
    conn_reset_request(c);
    c->state = CS_HEAD;
    c->deadline = g_now + c->srv->idle_timeout;
    conn_flush(c);
    if (c->dead || c->in_process)
        return; /* conn_process's loop picks up any pipelined request */
    if (buf_readable(&c->rbuf) > 0 || c->rd_eof)
        conn_process(c);
}

static void conn_send_error(conn_t *c, int status, const char *msg, int close)
{
    if (c->uc) {
        uconn_t *uc = c->uc;
        c->uc = NULL;
        uc->c = NULL;
        uconn_close(uc);
    }
    if (c->up) {
        c->up->active--;
        c->up = NULL;
    }
    if (c->resp_head_sent) {
        /* can't signal an error any more: drop the connection */
        c->resp_status = c->resp_status ? c->resp_status : status;
        conn_log_access(c);
        conn_close(c);
        return;
    }
    if (close)
        c->close_after_write = 1;
    char body[512];
    int n = snprintf(body, sizeof body, "%d %s\n%s%s", status, http_status_reason(status), msg ? msg : "", msg ? "\n" : "");
    if (n < 0)
        n = 0;
    conn_write_simple_response(c, status, "text/plain; charset=utf-8", body, (size_t)n, NULL, 0, NULL);
    c->state = CS_LOCAL;
    conn_next_request(c);
}

/* ------------------------------------------------------------------ */
/* Upstream connections                                                */
/* ------------------------------------------------------------------ */

static void uconn_list_add(uconn_t *uc)
{
    uc->next = g_uconns;
    uc->prev = NULL;
    if (g_uconns)
        g_uconns->prev = uc;
    g_uconns = uc;
    g_stats.active_uconns++;
}

static void uconn_list_del(uconn_t *uc)
{
    if (uc->prev)
        uc->prev->next = uc->next;
    else
        g_uconns = uc->next;
    if (uc->next)
        uc->next->prev = uc->prev;
    g_stats.active_uconns--;
}

static void idle_unlink(uconn_t *uc)
{
    upstream_t *u = uc->up;
    uconn_t **pp = &u->idle;
    while (*pp) {
        if (*pp == uc) {
            *pp = uc->idle_next;
            u->nidle--;
            uc->idle_next = NULL;
            return;
        }
        pp = &(*pp)->idle_next;
    }
}

static void uconn_destroy(ev_t *e)
{
    uconn_t *uc = (uconn_t *)e;
    buf_free(&uc->rbuf);
    buf_free(&uc->wbuf);
    http_resp_free(&uc->resp);
    config_unref(uc->cfg);
    free(uc);
}

static void uconn_close(uconn_t *uc)
{
    if (uc->dead)
        return;
    uc->dead = 1;
    if (uc->state == US_IDLE)
        idle_unlink(uc);
    if (uc->c) {
        uc->c->uc = NULL;
        uc->c = NULL;
    }
    uconn_list_del(uc);
    ev_retire(&uc->ev);
}

static uconn_t *uconn_connect(upstream_t *u, pool_t *p, config_t *cfg)
{
    int fd = socket(u->addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return NULL;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    int rc = connect(fd, (struct sockaddr *)&u->addr, u->addrlen);
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return NULL;
    }
    uconn_t *uc = xcalloc(1, sizeof *uc);
    uc->ev.fd = fd;
    uc->ev.cb = uconn_cb;
    uc->ev.destroy = uconn_destroy;
    uc->up = u;
    uc->pool = p;
    uc->cfg = cfg;
    config_ref(cfg);
    uc->state = US_CONNECTING;
    uc->connected = rc == 0;
    buf_init(&uc->rbuf);
    buf_init(&uc->wbuf);
    http_resp_init(&uc->resp);
    uconn_list_add(uc);
    ev_add(&uc->ev, EPOLLOUT);
    return uc;
}

static uconn_t *uconn_take_idle(upstream_t *u)
{
    uconn_t *uc = u->idle;
    if (!uc)
        return NULL;
    u->idle = uc->idle_next;
    u->nidle--;
    uc->idle_next = NULL;
    uc->state = US_ACTIVE;
    uc->reused = 1;
    uc->head_done = 0;
    uc->got_bytes = 0;
    http_resp_free(&uc->resp);
    http_resp_init(&uc->resp);
    buf_reset(&uc->rbuf);
    buf_reset(&uc->wbuf);
    return uc;
}

/* Return a finished upstream connection to its idle pool, or close it. */
static void uconn_release(uconn_t *uc, int reusable)
{
    conn_t *c = uc->c;
    if (c) {
        c->uc = NULL;
        uc->c = NULL;
    }
    pool_t *p = uc->pool;
    if (!reusable || uc->cfg != g_cfg || p->keepalive_idle <= 0 || uc->up->nidle >= p->keepalive_idle ||
        buf_readable(&uc->rbuf) > 0 || g_shutting_down) {
        uconn_close(uc);
        return;
    }
    uc->state = US_IDLE;
    uc->idle_since = g_now;
    uc->idle_next = uc->up->idle;
    uc->up->idle = uc;
    uc->up->nidle++;
    http_resp_free(&uc->resp);
    http_resp_init(&uc->resp);
    uc->head_done = 0;
    uc->got_bytes = 0;
    buf_reset(&uc->rbuf);
    buf_reset(&uc->wbuf);
    ev_mod(&uc->ev, EPOLLIN | EPOLLRDHUP);
}

static int method_idempotent(const char *m)
{
    return strcmp(m, "GET") == 0 || strcmp(m, "HEAD") == 0 || strcmp(m, "OPTIONS") == 0 ||
           strcmp(m, "PUT") == 0 || strcmp(m, "DELETE") == 0 || strcmp(m, "TRACE") == 0;
}

/*
 * An upstream attempt failed. Decide between retrying on another upstream and
 * returning an error to the client. `retryable` says whether the request can
 * safely be re-sent (nothing of the response was seen yet).
 */
static void uconn_fail(uconn_t *uc, const char *reason, int status, int retryable)
{
    conn_t *c = uc->c;
    upstream_t *u = uc->up;
    pool_t *p = uc->pool;
    LOGD("upstream %s: %s", u->hostport, reason);
    g_stats.upstream_errors++;
    upstream_report_failure(p, u, g_now, reason);
    uconn_close(uc);
    if (!c)
        return;
    if (c->up) {
        c->up->active--;
        c->up = NULL;
    }
    if (c->resp_head_sent && !c->resp_committed && c->state == CS_UPSTREAM) {
        /* the response head is still only buffered: drop it and answer with an error */
        c->wbuf.len = c->wbuf.off + c->resp_head_mark;
        c->resp_head_sent = 0;
        c->resp_status = 0;
        c->resp_bytes = 0;
        c->close_after_write = c->pre_head_close;
        retryable = 0; /* the upstream did respond, just badly */
    }
    if (c->resp_head_sent) {
        LOGW("upstream %s failed mid-response: %s", u->hostport, reason);
        c->close_after_write = 1;
        conn_log_access(c);
        conn_close(c);
        return;
    }
    if (retryable && c->attempts <= p->retries) {
        g_stats.retries++;
        LOGD("retrying request on another upstream (attempt %d)", c->attempts + 1);
        conn_try_upstream(c);
        return;
    }
    char msg[256];
    snprintf(msg, sizeof msg, "upstream %s: %s", u->hostport, reason);
    conn_send_error(c, status, msg, 0);
}

/* Build the request to send upstream into uc->wbuf. */
static void build_upstream_request(conn_t *c, uconn_t *uc)
{
    http_req_t *r = &c->req;
    pool_t *p = c->pool;
    buf_t *out = &uc->wbuf;
    buf_reset(out);
    /* always send the origin-form target, even if the client used absolute-form */
    if (str_has_prefix(r->uri, "http://") || str_has_prefix(r->uri, "https://"))
        buf_printf(out, "%s %s%s%s HTTP/1.1\r\n", r->method, r->path, *r->query ? "?" : "", r->query);
    else
        buf_printf(out, "%s %s HTTP/1.1\r\n", r->method, r->uri);

    hlist_t h = { 0 };
    const char *conn_hdr = http_hdr_get(r->hdrs, r->nhdr, "Connection");
    const char *orig_host = http_hdr_get(r->hdrs, r->nhdr, "Host");
    int has_body = r->content_length >= 0 || r->chunked;

    /* Host first */
    if (p->preserve_host && orig_host && *orig_host)
        hlist_add(&h, "Host", orig_host);
    else
        hlist_add(&h, "Host", c->up->hostport);

    for (int i = 0; i < r->nhdr; i++) {
        const char *n = r->hdrs[i].name;
        if (strcasecmp(n, "Host") == 0 || strcasecmp(n, "Content-Length") == 0 ||
            strcasecmp(n, "Expect") == 0 || strcasecmp(n, "X-Forwarded-For") == 0 ||
            strcasecmp(n, "X-Forwarded-Proto") == 0 || strcasecmp(n, "X-Forwarded-Host") == 0 ||
            strcasecmp(n, "X-Real-IP") == 0)
            continue; /* framing headers are regenerated; forwarding headers are proxy-owned */
        if (http_hdr_is_hop_by_hop(n)) {
            if (r->upgrade && strcasecmp(n, "Upgrade") == 0)
                hlist_add(&h, n, r->hdrs[i].value);
            continue;
        }
        if (http_hdr_connection_has(conn_hdr, n))
            continue; /* header nominated as hop-by-hop */
        hlist_add(&h, n, r->hdrs[i].value);
    }
    if (r->upgrade)
        hlist_add(&h, "Connection", "Upgrade");
    else
        hlist_add(&h, "Connection", p->keepalive_idle > 0 ? "keep-alive" : "close");
    if (has_body || buf_readable(&r->body) > 0) {
        char tmp[32];
        snprintf(tmp, sizeof tmp, "%zu", buf_readable(&r->body));
        hlist_add(&h, "Content-Length", tmp);
    }
    /* forwarding headers, Caddy-style */
    {
        buf_t xff;
        buf_init(&xff);
        const char *prev = http_hdr_get(r->hdrs, r->nhdr, "X-Forwarded-For");
        if (prev && *prev) {
            buf_puts(&xff, prev);
            buf_puts(&xff, ", ");
        }
        buf_puts(&xff, c->peer_ip);
        buf_append(&xff, "", 1);
        hlist_add(&h, "X-Forwarded-For", buf_rptr(&xff));
        buf_free(&xff);
    }
    hlist_add(&h, "X-Forwarded-Proto", c->ctx.tls ? "https" : "http");
    if (orig_host)
        hlist_add(&h, "X-Forwarded-Host", orig_host);
    hlist_add(&h, "X-Real-IP", c->peer_ip);
    if (c->srv->n_hdr_up)
        hlist_apply_ops(&h, c->srv->hdr_up, c->srv->n_hdr_up, c);
    hlist_apply_ops(&h, p->hdr_up, p->n_hdr_up, c);
    hlist_write(&h, out);
    hlist_free(&h);
    buf_puts(out, "\r\n");
    if (buf_readable(&r->body) > 0)
        buf_append(out, buf_rptr(&r->body), buf_readable(&r->body));
}

static void conn_try_upstream(conn_t *c)
{
    pool_t *p = c->pool;
    int idx = -1;
    upstream_t *u = pool_select(p, &c->ctx, c->tried, g_now, &idx, c->lb_why, sizeof c->lb_why);
    if (!u) {
        if (c->attempts == 0)
            conn_send_error(c, 503, "no healthy upstreams available", 0);
        else
            conn_send_error(c, 502, "all upstreams failed", 0);
        return;
    }
    c->tried |= (uint64_t)1 << idx;
    c->attempts++;
    c->up = u;
    u->active++;
    u->requests++;
    uconn_t *uc = uconn_take_idle(u);
    if (!uc) {
        uc = uconn_connect(u, p, c->cfg);
        if (!uc) {
            char reason[160];
            snprintf(reason, sizeof reason, "connect: %s", strerror(errno));
            upstream_report_failure(p, u, g_now, reason);
            g_stats.upstream_errors++;
            u->active--;
            c->up = NULL;
            if (c->attempts <= p->retries) {
                conn_try_upstream(c);
            } else {
                conn_send_error(c, 502, reason, 0);
            }
            return;
        }
    }
    uc->c = c;
    c->uc = uc;
    c->state = CS_UPSTREAM;
    c->deadline = g_now + p->connect_timeout;
    build_upstream_request(c, uc);
    if (uc->state == US_ACTIVE || uc->connected) {
        uc->state = US_ACTIVE;
        c->deadline = g_now + p->response_timeout;
        int rc = fd_flush(uc->ev.fd, &uc->wbuf);
        if (rc < 0) {
            uconn_fail(uc, "write failed", 502, uc->reused || method_idempotent(c->req.method));
            return;
        }
        ev_mod(&uc->ev, EPOLLIN | EPOLLRDHUP | (rc == 0 ? EPOLLOUT : 0));
    }
    conn_update_mask(c);
}

/* Build the response head for the client from the upstream response. */
static void build_client_response_head(conn_t *c, uconn_t *uc)
{
    http_resp_t *r = &uc->resp;
    pool_t *p = c->pool;
    int is_head = strcmp(c->req.method, "HEAD") == 0;
    int tunnel = r->status == 101;

    /* framing */
    if (tunnel) {
        c->resp_mode = RM_NONE;
    } else if (is_head || r->status / 100 == 1 || r->status == 204 || r->status == 304) {
        c->resp_mode = RM_NONE;
    } else if (r->chunked) {
        c->resp_mode = c->req.minor >= 1 ? RM_CHUNKED : RM_DECHUNK;
    } else if (r->content_length >= 0) {
        c->resp_mode = RM_LENGTH;
        c->resp_remaining = r->content_length;
    } else {
        c->resp_mode = RM_CLOSE;
    }

    /* A bodiless response that still advertises a body (e.g. a 204 with
     * Content-Length) would leave stray bytes on the connection: don't pool it. */
    c->upstream_reusable = r->keep_alive && c->resp_mode != RM_CLOSE &&
                           !(c->resp_mode == RM_NONE && !is_head && (r->content_length > 0 || r->chunked));

    /* compression: the body is re-framed as chunked (HTTP/1.1) or close-delimited */
    const char *encname = NULL;
    if (c->resp_mode != RM_NONE)
        encname = conn_pick_encoding(c, http_hdr_get(r->hdrs, r->nhdr, "Content-Type"),
                                     c->resp_mode == RM_LENGTH ? r->content_length : -1, r->status,
                                     http_hdr_get(r->hdrs, r->nhdr, "Content-Encoding"));
    if (encname && (c->enc = encoder_new(encname)) != NULL) {
        c->body_sync = c->resp_mode != RM_LENGTH;
        if (c->resp_mode == RM_CHUNKED)
            c->resp_mode = RM_DECHUNK;
        if (c->req.minor >= 1)
            c->out_chunked = 1;
    }
    int keep = c->req.keep_alive && !g_shutting_down && !tunnel;
    if (c->enc) {
        if (!c->out_chunked)
            keep = 0;
    } else if (c->resp_mode == RM_CLOSE || c->resp_mode == RM_DECHUNK) {
        keep = 0;
    }
    if (!keep)
        c->close_after_write = 1;

    hlist_t h = { 0 };
    const char *conn_hdr = http_hdr_get(r->hdrs, r->nhdr, "Connection");
    for (int i = 0; i < r->nhdr; i++) {
        const char *n = r->hdrs[i].name;
        if (strcasecmp(n, "Content-Length") == 0) {
            if (is_head || (c->resp_mode == RM_NONE && !tunnel && r->status != 204 && r->status / 100 != 1))
                hlist_add(&h, n, r->hdrs[i].value);
            continue;
        }
        if (http_hdr_is_hop_by_hop(n)) {
            if (tunnel && strcasecmp(n, "Upgrade") == 0)
                hlist_add(&h, n, r->hdrs[i].value);
            continue;
        }
        if (http_hdr_connection_has(conn_hdr, n))
            continue;
        hlist_add(&h, n, r->hdrs[i].value);
    }
    char tmp[32];
    if (c->enc) {
        hlist_del(&h, "Content-Length");
        hlist_add(&h, "Content-Encoding", encode_name(c->enc));
        hlist_add(&h, "Vary", "Accept-Encoding");
        if (c->out_chunked)
            hlist_add(&h, "Transfer-Encoding", "chunked");
    } else {
        switch (c->resp_mode) {
        case RM_LENGTH:
            snprintf(tmp, sizeof tmp, "%lld", (long long)r->content_length);
            hlist_add(&h, "Content-Length", tmp);
            break;
        case RM_CHUNKED:
            hlist_add(&h, "Transfer-Encoding", "chunked");
            break;
        default:
            break;
        }
    }
    if (tunnel)
        hlist_add(&h, "Connection", "Upgrade");
    else
        hlist_add(&h, "Connection", keep ? "keep-alive" : "close");
    if (c->srv->n_hdr_down)
        hlist_apply_ops(&h, c->srv->hdr_down, c->srv->n_hdr_down, c);
    hlist_apply_ops(&h, p->hdr_down, p->n_hdr_down, c);

    buf_printf(&c->wbuf, "HTTP/1.1 %d %s\r\n", r->status, *r->reason ? r->reason : http_status_reason(r->status));
    hlist_write(&h, &c->wbuf);
    buf_puts(&c->wbuf, "\r\n");
    hlist_free(&h);
    c->resp_status = r->status;
    c->resp_head_sent = 1;
}

/* The response to the client is complete. */
static void conn_response_done(conn_t *c)
{
    uconn_t *uc = c->uc;
    upstream_t *u = c->up;
    pool_t *p = c->pool;
    conn_body_finish(c);
    if (u) {
        if (p->unhealthy_5xx && c->resp_status >= 500 && c->resp_status <= 599)
            upstream_report_failure(p, u, g_now, "5xx response");
        else
            upstream_report_success(p, u);
        u->active--;
        c->up = NULL;
    }
    if (uc) {
        uconn_release(uc, c->upstream_reusable);
    }
    c->deadline = 0;
    conn_next_request(c);
}

/* Switch client and upstream into raw tunnel mode after a 101 response. */
static void conn_start_tunnel(conn_t *c, uconn_t *uc)
{
    c->state = CS_TUNNEL;
    uc->state = US_TUNNEL;
    c->deadline = 0;
    /* bytes already buffered on either side belong to the tunnel */
    if (buf_readable(&uc->rbuf) > 0) {
        buf_append(&c->wbuf, buf_rptr(&uc->rbuf), buf_readable(&uc->rbuf));
        buf_reset(&uc->rbuf);
    }
    if (buf_readable(&c->rbuf) > 0) {
        buf_append(&uc->wbuf, buf_rptr(&c->rbuf), buf_readable(&c->rbuf));
        buf_reset(&c->rbuf);
    }
    conn_flush(c);
    if (c->dead)
        return;
    int rc = fd_flush(uc->ev.fd, &uc->wbuf);
    if (rc < 0) {
        conn_close(c);
        return;
    }
    ev_mod(&uc->ev, EPOLLIN | EPOLLRDHUP | (rc == 0 ? EPOLLOUT : 0));
}

/* Forward response body bytes from uc->rbuf to the client according to resp_mode. */
static void uconn_forward_body(uconn_t *uc)
{
    conn_t *c = uc->c;
    size_t avail = buf_readable(&uc->rbuf);
    const char *data = buf_rptr(&uc->rbuf);
    int done = 0;
    switch (c->resp_mode) {
    case RM_NONE:
        done = 1;
        break;
    case RM_LENGTH: {
        size_t take = avail;
        if ((int64_t)take > c->resp_remaining)
            take = (size_t)c->resp_remaining;
        c->resp_remaining -= (int64_t)take;
        done = c->resp_remaining == 0;
        conn_body_emit(c, data, take, c->body_sync && !done ? 1 : 0);
        buf_consume(&uc->rbuf, take);
        break;
    }
    case RM_CHUNKED: {
        size_t consumed = 0;
        if (http_chunk_scan(&c->resp_cs, data, avail, &consumed, NULL) < 0) {
            uconn_fail(uc, "malformed chunked response", 502, 0);
            return;
        }
        buf_append(&c->wbuf, data, consumed);
        buf_consume(&uc->rbuf, consumed);
        c->resp_bytes += consumed;
        done = c->resp_cs.done;
        break;
    }
    case RM_DECHUNK: {
        size_t consumed = 0;
        buf_reset(&c->dechunk);
        if (http_chunk_scan(&c->resp_cs, data, avail, &consumed, &c->dechunk) < 0) {
            uconn_fail(uc, "malformed chunked response", 502, 0);
            return;
        }
        buf_consume(&uc->rbuf, consumed);
        done = c->resp_cs.done;
        conn_body_emit(c, buf_rptr(&c->dechunk), buf_readable(&c->dechunk), c->body_sync && !done ? 1 : 0);
        buf_reset(&c->dechunk);
        break;
    }
    case RM_CLOSE:
        conn_body_emit(c, data, avail, c->body_sync ? 1 : 0);
        buf_consume(&uc->rbuf, avail);
        break;
    }
    conn_flush(c);
    if (c->dead || uc->dead)
        return; /* client went away */
    if (done) {
        conn_response_done(c);
        return;
    }
    if (buf_readable(&c->wbuf) > WBUF_HIGH_WATER && !c->upstream_paused) {
        c->upstream_paused = 1;
        ev_mod(&uc->ev, EPOLLRDHUP | (buf_readable(&uc->wbuf) ? EPOLLOUT : 0));
    }
}

static void uconn_on_response_data(uconn_t *uc)
{
    conn_t *c = uc->c;
    while (!uc->head_done) {
        size_t consumed = 0;
        int rc = http_parse_response_head(&uc->resp, buf_rptr(&uc->rbuf), buf_readable(&uc->rbuf), &consumed);
        if (rc == 0)
            return;
        if (rc < 0) {
            uconn_fail(uc, rc == -2 ? "response head too large" : "malformed response", 502, 0);
            return;
        }
        buf_consume(&uc->rbuf, consumed);
        if (uc->resp.status / 100 == 1 && uc->resp.status != 101) {
            /* interim response: discard and keep parsing */
            http_resp_free(&uc->resp);
            http_resp_init(&uc->resp);
            continue;
        }
        if (uc->resp.status == 101 && !c->req.upgrade) {
            uconn_fail(uc, "unexpected 101 response", 502, 0);
            return;
        }
        uc->head_done = 1;
        c->deadline = 0;
        c->resp_head_mark = buf_readable(&c->wbuf);
        c->pre_head_close = c->close_after_write;
        build_client_response_head(c, uc);
        if (uc->resp.status == 101) {
            conn_start_tunnel(c, uc);
            return;
        }
    }
    uconn_forward_body(uc);
}

static void uconn_cb(ev_t *e, uint32_t events)
{
    uconn_t *uc = (uconn_t *)e;
    conn_t *c = uc->c;

    if (uc->state == US_IDLE) {
        /* an idle connection became readable: the server closed it or sent junk */
        uconn_close(uc);
        return;
    }
    if (uc->state == US_CONNECTING) {
        if (events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
            int err = 0;
            socklen_t el = sizeof err;
            if (getsockopt(uc->ev.fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0)
                err = errno;
            if (err) {
                char reason[160];
                snprintf(reason, sizeof reason, "connect: %s", strerror(err));
                uconn_fail(uc, reason, 502, 1);
                return;
            }
            uc->state = US_ACTIVE;
            uc->connected = 1;
            if (c)
                c->deadline = g_now + uc->pool->response_timeout;
            int rc = fd_flush(uc->ev.fd, &uc->wbuf);
            if (rc < 0) {
                uconn_fail(uc, "write failed", 502, 1);
                return;
            }
            ev_mod(&uc->ev, EPOLLIN | EPOLLRDHUP | (rc == 0 ? EPOLLOUT : 0));
        }
        return;
    }

    if (events & EPOLLOUT) {
        int rc = fd_flush(uc->ev.fd, &uc->wbuf);
        if (rc < 0) {
            if (uc->state == US_TUNNEL) {
                if (c)
                    conn_close(c);
                else
                    uconn_close(uc);
                return;
            }
            uconn_fail(uc, "write failed", 502, !uc->got_bytes && (uc->reused || (c && method_idempotent(c->req.method))));
            return;
        }
        if (rc == 1) {
            uint32_t m = EPOLLRDHUP;
            if (!(c && c->upstream_paused))
                m |= EPOLLIN;
            ev_mod(&uc->ev, m);
            if (uc->state == US_TUNNEL && c)
                conn_update_mask(c); /* resume client reads */
        }
    }

    if (events & (EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
        if (!c) {
            uconn_close(uc);
            return;
        }
        if (c->upstream_paused && !(events & (EPOLLHUP | EPOLLERR)))
            return;
        for (;;) {
            ssize_t r = fd_read(uc->ev.fd, &uc->rbuf);
            if (r > 0) {
                uc->got_bytes = 1;
                if (uc->state == US_TUNNEL) {
                    buf_append(&c->wbuf, buf_rptr(&uc->rbuf), buf_readable(&uc->rbuf));
                    buf_reset(&uc->rbuf);
                    conn_flush(c);
                    if (c->dead || uc->dead)
                        return;
                    if (buf_readable(&c->wbuf) > WBUF_HIGH_WATER) {
                        c->upstream_paused = 1;
                        ev_mod(&uc->ev, EPOLLRDHUP | (buf_readable(&uc->wbuf) ? EPOLLOUT : 0));
                        return;
                    }
                    continue;
                }
                uconn_on_response_data(uc);
                if (uc->dead || c->dead || uc->state != US_ACTIVE)
                    return; /* response finished, failed, or tunnel started */
                if (c->upstream_paused)
                    return;
                continue;
            }
            if (r == -1)
                return; /* would block */
            if (r == 0) {
                /* EOF from upstream */
                if (uc->state == US_TUNNEL) {
                    conn_finish(c);
                    return;
                }
                if (!uc->head_done) {
                    int retry = !uc->got_bytes && (uc->reused || method_idempotent(c->req.method));
                    uconn_fail(uc, uc->got_bytes ? "connection closed before response head" : "connection closed without response", 502, retry);
                    return;
                }
                if (c->resp_mode == RM_CLOSE) {
                    conn_response_done(c);
                    return;
                }
                uconn_fail(uc, "response truncated", 502, 0);
                return;
            }
            /* error */
            if (uc->state == US_TUNNEL) {
                conn_finish(c);
                return;
            }
            uconn_fail(uc, "read error", 502, !uc->got_bytes && uc->reused);
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Request dispatch                                                    */
/* ------------------------------------------------------------------ */

/* Apply a route's rewrites to the request path/query/uri. */
static void apply_rewrites(conn_t *c, const route_t *r)
{
    http_req_t *q = &c->req;
    for (int i = 0; i < r->nrw; i++) {
        const rewrite_t *rw = &r->rw[i];
        char *npath = NULL, *nquery = NULL;
        switch (rw->kind) {
        case RW_URI: {
            buf_t b;
            buf_init(&b);
            expand_placeholders(rw->a, c, &b);
            buf_append(&b, "", 1);
            const char *qm = strchr(b.data, '?');
            if (qm) {
                npath = xstrndup(b.data, (size_t)(qm - b.data));
                nquery = xstrdup(qm + 1);
            } else {
                npath = xstrdup(b.data);
            }
            buf_free(&b);
            break;
        }
        case RW_STRIP_PREFIX:
            if (str_has_prefix(q->path, rw->a)) {
                const char *rest = q->path + strlen(rw->a);
                npath = *rest == '/' ? xstrdup(rest) : *rest ? NULL : xstrdup("/");
                if (!npath && *rest) {
                    /* prefix matched mid-segment: only strip when it ends on a boundary */
                    npath = NULL;
                }
            }
            break;
        case RW_STRIP_SUFFIX: {
            size_t pl = strlen(q->path), sl = strlen(rw->a);
            if (pl >= sl && strcmp(q->path + pl - sl, rw->a) == 0)
                npath = pl == sl ? xstrdup("/") : xstrndup(q->path, pl - sl);
            break;
        }
        case RW_REPLACE: {
            size_t sl = strlen(rw->a);
            if (!sl)
                break;
            buf_t b;
            buf_init(&b);
            const char *p = q->path;
            int changed = 0;
            while (*p) {
                if (strncmp(p, rw->a, sl) == 0) {
                    buf_puts(&b, rw->b ? rw->b : "");
                    p += sl;
                    changed = 1;
                } else {
                    buf_append(&b, p++, 1);
                }
            }
            buf_append(&b, "", 1);
            if (changed)
                npath = xstrdup(b.data);
            buf_free(&b);
            break;
        }
        }
        if (!npath)
            continue;
        if (!*npath) {
            free(npath);
            npath = xstrdup("/");
        }
        if (!q->orig_path)
            q->orig_path = xstrdup(q->path);
        free(q->path);
        q->path = npath;
        if (nquery) {
            free(q->query);
            q->query = nquery;
        }
        buf_t u;
        buf_init(&u);
        buf_puts(&u, q->path);
        if (*q->query) {
            buf_puts(&u, "?");
            buf_puts(&u, q->query);
        }
        buf_append(&u, "", 1);
        free(q->uri_owned);
        q->uri_owned = xstrdup(u.data);
        q->uri = q->uri_owned;
        buf_free(&u);
    }
}

static void conn_respond_unauthorized(conn_t *c, const basic_auth_t *a)
{
    char extra[512];
    snprintf(extra, sizeof extra, "WWW-Authenticate: Basic realm=\"%s\", charset=\"UTF-8\"\r\n", a->realm);
    const char *body = "401 Unauthorized\n";
    conn_write_simple_response(c, 401, "text/plain; charset=utf-8", body, strlen(body), NULL, 0, extra);
    c->state = CS_LOCAL;
    conn_next_request(c);
}

static void conn_serve_files(conn_t *c, route_t *r);
static void file_pump(conn_t *c);

static void conn_dispatch(conn_t *c)
{
    http_req_t *r = &c->req;
    g_stats.requests++;
    c->ctx.req = r;
    c->ctx.peer = (struct sockaddr *)&c->peer;
    c->ctx.peerlen = c->peerlen;
    snprintf(c->ctx.peer_ip, sizeof c->ctx.peer_ip, "%s", c->peer_ip);
#ifdef LIMER_TLS
    c->ctx.tls = c->ssl != NULL;
#else
    c->ctx.tls = 0;
#endif
    if (c->srv->is_admin) {
        admin_handle(c);
        return;
    }

    /* ACME http-01 challenges are answered on plain-http listeners */
    if (!c->ctx.tls && str_has_prefix(r->path, "/.well-known/acme-challenge/")) {
        buf_t ka;
        buf_init(&ka);
        if (acme_challenge_lookup(c->cfg, r->path + 28, &ka)) {
            conn_write_simple_response(c, 200, "text/plain", buf_rptr(&ka), buf_readable(&ka), NULL, 0, NULL);
            buf_free(&ka);
            c->state = CS_LOCAL;
            conn_next_request(c);
            return;
        }
        buf_free(&ka);
    }

    /* implicit http -> https redirect site */
    if (c->srv->redirect_https) {
        if (c->cfg->acme_disabled == 2) {
            conn_send_error(c, 404, "this site is served over https", 0);
            return;
        }
        char host[256];
        host_only(http_hdr_get(r->hdrs, r->nhdr, "Host"), host, sizeof host);
        if (!host[0])
            snprintf(host, sizeof host, "%s", c->srv->nhosts ? c->srv->hosts[0] : "localhost");
        char loc[2048];
        if (c->srv->port == 443)
            snprintf(loc, sizeof loc, "Location: https://%s%s\r\n", host, r->uri);
        else
            snprintf(loc, sizeof loc, "Location: https://%s:%d%s\r\n", host, c->srv->port, r->uri);
        c->route = c->srv->routes[0];
        conn_write_simple_response(c, 308, "text/plain; charset=utf-8", "", 0, NULL, 0, loc);
        c->state = CS_LOCAL;
        conn_next_request(c);
        return;
    }

    if (c->srv->auth && !auth_verify(c->srv->auth, http_hdr_get(r->hdrs, r->nhdr, "Authorization"))) {
        conn_respond_unauthorized(c, c->srv->auth);
        return;
    }

    route_t *route = NULL;
    for (int i = 0; i < c->srv->nroutes; i++)
        if (route_matches(c->srv->routes[i], &c->ctx)) {
            route = c->srv->routes[i];
            break;
        }
    c->route = route;
    if (!route) {
        conn_send_error(c, 404, "no route matched the request", 0);
        return;
    }
    if (route->auth && !auth_verify(route->auth, http_hdr_get(r->hdrs, r->nhdr, "Authorization"))) {
        conn_respond_unauthorized(c, route->auth);
        return;
    }
    if (route->nrw)
        apply_rewrites(c, route);

    switch (route->kind) {
    case ROUTE_RESPOND: {
        const char *body = route->resp_body ? route->resp_body : "";
        buf_t eb;
        buf_init(&eb);
        expand_placeholders(body, c, &eb);
        buf_append(&eb, "", 1);
        conn_write_simple_response(c, route->resp_status, content_type_for(eb.data), eb.data, eb.len - 1,
                                   route->hdr_down, route->n_hdr_down, NULL);
        buf_free(&eb);
        c->state = CS_LOCAL;
        conn_next_request(c);
        return;
    }
    case ROUTE_ERROR: {
        char body[1024];
        int n = snprintf(body, sizeof body, "%d %s\n%s%s", route->resp_status, http_status_reason(route->resp_status),
                         route->resp_body ? route->resp_body : "", route->resp_body ? "\n" : "");
        conn_write_simple_response(c, route->resp_status, "text/plain; charset=utf-8", body, (size_t)(n < 0 ? 0 : n),
                                   route->hdr_down, route->n_hdr_down, NULL);
        c->state = CS_LOCAL;
        conn_next_request(c);
        return;
    }
    case ROUTE_ABORT:
        c->resp_status = 0;
        conn_log_access(c);
        conn_close(c);
        return;
    case ROUTE_REDIRECT: {
        buf_t loc;
        buf_init(&loc);
        expand_placeholders(route->resp_body, c, &loc);
        buf_append(&loc, "", 1);
        char extra[2048];
        snprintf(extra, sizeof extra, "Location: %s\r\n", buf_rptr(&loc));
        buf_free(&loc);
        conn_write_simple_response(c, route->resp_status, "text/plain; charset=utf-8", "", 0,
                                   route->hdr_down, route->n_hdr_down, extra);
        c->state = CS_LOCAL;
        conn_next_request(c);
        return;
    }
    case ROUTE_FILES:
        conn_serve_files(c, route);
        return;
    case ROUTE_PROXY:
    default:
        c->pool = route->pool;
        c->tried = 0;
        c->attempts = 0;
        conn_try_upstream(c);
        return;
    }
}

/* Drive the request parser over rbuf. */
static void conn_process(conn_t *c)
{
    if (c->in_process)
        return;
    c->in_process = 1;
    for (;;) {
        if (c->state == CS_HEAD) {
            if (buf_readable(&c->rbuf) == 0) {
                if (c->rd_eof) {
                    c->in_process = 0;
                    conn_finish(c);
                    return;
                }
                break;
            }
            if (!c->got_request_bytes) {
                c->got_request_bytes = 1;
                c->req_start = g_now;
                c->deadline = g_now + c->srv->read_timeout;
            }
            size_t consumed = 0;
            int rc = http_parse_request_head(&c->req, buf_rptr(&c->rbuf), buf_readable(&c->rbuf), &consumed);
            if (rc == 0) {
                if (c->rd_eof) {
                    c->in_process = 0;
                    if (c->requests == 0 || buf_readable(&c->rbuf) > 0)
                        conn_send_error(c, 400, "incomplete request", 1);
                    else
                        conn_finish(c);
                    return;
                }
                break;
            }
            if (rc == -2) {
                c->in_process = 0;
                conn_send_error(c, 431, "request head too large", 1);
                return;
            }
            if (rc < 0) {
                c->in_process = 0;
                conn_send_error(c, 400, "malformed request", 1);
                return;
            }
            buf_consume(&c->rbuf, consumed);
            {
                char host[256];
                host_only(http_hdr_get(c->req.hdrs, c->req.nhdr, "Host"), host, sizeof host);
                server_t *srv = select_server(c->cfg, c->listen_addr, host[0] ? host : NULL);
                if (!srv) {
                    c->in_process = 0;
                    conn_send_error(c, 404, "no site configured for this host", 0);
                    return;
                }
#ifdef LIMER_TLS
                if (c->ssl && srv->tls_mode == TLS_NONE)
                    srv = c->srv; /* never jump from a TLS site to a plain one */
#endif
                c->srv = srv;
            }
            if (c->req.content_length > (int64_t)c->srv->max_body) {
                c->in_process = 0;
                conn_send_error(c, 413, "request body exceeds max_body", 1);
                return;
            }
            c->state = CS_BODY;
            if (c->req.expect_100 && (c->req.chunked || c->req.content_length > 0) &&
                buf_readable(&c->rbuf) == 0 && c->req.minor >= 1) {
                buf_puts(&c->wbuf, "HTTP/1.1 100 Continue\r\n\r\n");
                c->expect_sent = 1;
                conn_flush(c);
                if (c->dead)
                    return;
            }
        }
        if (c->state == CS_BODY) {
            http_req_t *r = &c->req;
            int complete = 0;
            if (r->chunked) {
                size_t consumed = 0;
                if (http_chunk_scan(&r->cs, buf_rptr(&c->rbuf), buf_readable(&c->rbuf), &consumed, &r->body) < 0) {
                    c->in_process = 0;
                    conn_send_error(c, 400, "malformed chunked body", 1);
                    return;
                }
                buf_consume(&c->rbuf, consumed);
                if (buf_readable(&r->body) > c->srv->max_body) {
                    c->in_process = 0;
                    conn_send_error(c, 413, "request body exceeds max_body", 1);
                    return;
                }
                complete = r->cs.done;
            } else if (r->content_length > 0) {
                size_t need = (size_t)r->content_length - buf_readable(&r->body);
                size_t take = buf_readable(&c->rbuf);
                if (take > need)
                    take = need;
                buf_append(&r->body, buf_rptr(&c->rbuf), take);
                buf_consume(&c->rbuf, take);
                complete = buf_readable(&r->body) == (size_t)r->content_length;
            } else {
                complete = 1;
            }
            if (!complete) {
                if (c->rd_eof) {
                    c->in_process = 0;
                    conn_send_error(c, 400, "incomplete request body", 1);
                    return;
                }
                break;
            }
            conn_dispatch(c);
            if (c->dead)
                return;
            if (c->state == CS_HEAD)
                continue; /* answered locally; look for a pipelined request */
            c->in_process = 0;
            conn_update_mask(c);
            return;
        }
        break;
    }
    c->in_process = 0;
    conn_update_mask(c);
}

#ifdef LIMER_TLS
static void conn_tls_handshake(conn_t *c)
{
    ERR_clear_error();
    int r = SSL_do_handshake(c->ssl);
    if (r == 1) {
        c->tls_handshaking = 0;
        conn_update_mask(c);
        return;
    }
    int e = SSL_get_error(c->ssl, r);
    if (e == SSL_ERROR_WANT_READ) {
        ev_mod(&c->ev, EPOLLIN);
    } else if (e == SSL_ERROR_WANT_WRITE) {
        ev_mod(&c->ev, EPOLLOUT);
    } else {
        LOGD("tls handshake failed from %s: %s", c->peer_str, ERR_reason_error_string(ERR_peek_error()));
        conn_close(c);
    }
}
#endif

static void conn_on_readable(conn_t *c)
{
    int loops = 0;
    for (;;) {
        if (c->state == CS_TUNNEL) {
            if (!c->uc) {
                conn_finish(c);
                return;
            }
            if (buf_readable(&c->uc->wbuf) >= WBUF_HIGH_WATER)
                break;
            if (buf_reserve(&c->uc->wbuf, READ_CHUNK) < 0) {
                conn_close(c);
                return;
            }
            ssize_t r = conn_read_raw(c, buf_wptr(&c->uc->wbuf), buf_wavail(&c->uc->wbuf));
            if (r > 0) {
                buf_commit(&c->uc->wbuf, (size_t)r);
                int rc = fd_flush(c->uc->ev.fd, &c->uc->wbuf);
                if (rc < 0) {
                    conn_finish(c);
                    return;
                }
                ev_mod(&c->uc->ev, EPOLLRDHUP | (c->upstream_paused ? 0 : EPOLLIN) | (rc == 0 ? EPOLLOUT : 0));
                continue;
            }
            if (r == -1)
                break;
            /* EOF or error: tear down the tunnel after flushing */
            c->rd_eof = 1;
            conn_finish(c);
            return;
        }
        if (c->state == CS_UPSTREAM && buf_readable(&c->rbuf) >= RBUF_PIPELINE_CAP)
            break;
        if (buf_reserve(&c->rbuf, READ_CHUNK) < 0) {
            conn_close(c);
            return;
        }
        ssize_t r = conn_read_raw(c, buf_wptr(&c->rbuf), buf_wavail(&c->rbuf));
        if (r > 0) {
            buf_commit(&c->rbuf, (size_t)r);
            if (++loops < 8 && (size_t)r == READ_CHUNK)
                continue;
            break;
        }
        if (r == -1)
            break;
        if (r == 0) {
            c->rd_eof = 1;
            break;
        }
        conn_close(c);
        return;
    }
    if (c->state == CS_HEAD || c->state == CS_BODY) {
        conn_process(c);
        return;
    }
    if (c->state == CS_UPSTREAM) {
        if (c->rd_eof) {
            /* client gave up while we wait for the upstream */
            LOGD("client %s disconnected while waiting for upstream", c->peer_str);
            conn_close(c);
            return;
        }
        conn_update_mask(c);
        return;
    }
    if (c->rd_eof && (c->state == CS_LOCAL || c->state == CS_CLOSING)) {
        conn_update_mask(c);
    }
}

static void conn_cb(ev_t *e, uint32_t events)
{
    conn_t *c = (conn_t *)e;
#ifdef LIMER_TLS
    if (c->tls_handshaking) {
        if (events & (EPOLLERR | EPOLLHUP)) {
            conn_close(c);
            return;
        }
        conn_tls_handshake(c);
        return;
    }
#endif
    if (events & EPOLLERR) {
        conn_close(c);
        return;
    }
    if (events & EPOLLOUT) {
        conn_flush(c);
        if (c->dead)
            return;
        if (c->file_fd >= 0 && buf_readable(&c->wbuf) < WBUF_LOW_WATER) {
            file_pump(c);
            if (c->dead)
                return;
        }
    }
    if (events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP)) {
        if (c->state == CS_LOCAL || c->state == CS_CLOSING) {
            /* drain and detect EOF so we don't spin on a dead socket */
            char tmp[1024];
            ssize_t r = conn_read_raw(c, tmp, sizeof tmp);
            if (r == 0 || r == -2) {
                c->rd_eof = 1;
                if (buf_readable(&c->wbuf) == 0 || r == -2) {
                    conn_close(c);
                    return;
                }
                ev_mod(&c->ev, EPOLLOUT);
            }
            return;
        }
        conn_on_readable(c);
    }
}

/* ------------------------------------------------------------------ */
/* Listeners                                                           */
/* ------------------------------------------------------------------ */

static void listener_cb(ev_t *e, uint32_t events)
{
    listener_t *l = (listener_t *)e;
    for (int i = 0; i < 64; i++) {
        struct sockaddr_storage peer;
        socklen_t pl = sizeof peer;
        int fd = accept4(l->ev.fd, (struct sockaddr *)&peer, &pl, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return;
            if (errno == EMFILE || errno == ENFILE) {
                /* out of descriptors: stop accepting briefly instead of spinning */
                LOGW("accept on %s: %s; pausing accepts", l->addr, strerror(errno));
                l->paused_until = g_now + 0.2;
                ev_mod(&l->ev, 0);
                return;
            }
            if (errno == ECONNABORTED)
                continue;
            LOGE("accept on %s: %s", l->addr, strerror(errno));
            return;
        }
        if (g_cfg->max_connections > 0 && g_stats.active_conns >= g_cfg->max_connections) {
            LOGD("connection limit (%d) reached, refusing client", g_cfg->max_connections);
            close(fd);
            continue;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        conn_t *c = xcalloc(1, sizeof *c);
        c->ev.fd = fd;
        c->ev.cb = conn_cb;
        c->ev.destroy = conn_destroy;
        c->srv = l->default_srv;
        c->cfg = l->cfg;
        config_ref(c->cfg);
        snprintf(c->listen_addr, sizeof c->listen_addr, "%s", l->addr);
        memcpy(&c->peer, &peer, pl);
        c->peerlen = pl;
        sockaddr_to_str((struct sockaddr *)&peer, c->peer_ip, sizeof c->peer_ip, 0);
        sockaddr_to_str((struct sockaddr *)&peer, c->peer_str, sizeof c->peer_str, 1);
        buf_init(&c->rbuf);
        buf_init(&c->wbuf);
        buf_init(&c->enc_out);
        buf_init(&c->dechunk);
        c->file_fd = -1;
        http_req_init(&c->req);
        c->state = CS_HEAD;
        c->deadline = g_now + c->srv->read_timeout;
        conn_list_add(c);
        g_stats.active_conns++;
#ifdef LIMER_TLS
        if (l->tls && l->default_srv->ssl_ctx) {
            c->ssl = SSL_new(l->default_srv->ssl_ctx);
            SSL_set_fd(c->ssl, fd);
            SSL_set_app_data(c->ssl, c);
            SSL_set_accept_state(c->ssl);
            c->tls_handshaking = 1;
            ev_add(&c->ev, EPOLLIN);
            conn_tls_handshake(c);
            continue;
        }
#endif
        ev_add(&c->ev, EPOLLIN);
    }
}

static int bind_listener(const char *addr, char *err, size_t errlen)
{
    char *host;
    int port;
    if (parse_hostport(addr, &host, &port, 0) < 0) {
        snprintf(err, errlen, "invalid address '%s'", addr);
        return -1;
    }
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    int rc = getaddrinfo(*host ? host : NULL, portstr, &hints, &res);
    if (rc != 0) {
        snprintf(err, errlen, "cannot resolve '%s': %s", addr, gai_strerror(rc));
        free(host);
        return -1;
    }
    int fd = -1;
    int last_errno = 0;
    /* prefer IPv6 wildcard (dual-stack) for ":port" */
    for (int pass = 0; pass < 2 && fd < 0; pass++) {
        for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
            if (pass == 0 && ai->ai_family != AF_INET6)
                continue;
            if (pass == 1 && ai->ai_family == AF_INET6)
                continue;
            int s = socket(ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (s < 0) {
                last_errno = errno;
                continue;
            }
            int one = 1;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
            setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
            if (ai->ai_family == AF_INET6) {
                int zero = 0;
                setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
            }
            if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0 || listen(s, 1024) < 0) {
                last_errno = errno;
                close(s);
                continue;
            }
            fd = s;
            break;
        }
    }
    freeaddrinfo(res);
    free(host);
    if (fd < 0) {
        snprintf(err, errlen, "cannot bind '%s': %s", addr, strerror(last_errno ? last_errno : EADDRNOTAVAIL));
        return -1;
    }
    return fd;
}

static listener_t *find_listener(const char *addr)
{
    for (listener_t *l = g_listeners; l; l = l->next)
        if (strcmp(l->addr, addr) == 0)
            return l;
    return NULL;
}

static void listener_destroy(ev_t *e)
{
    listener_t *l = (listener_t *)e;
    config_unref(l->cfg);
    free(l->addr);
    free(l->servers);
    free(l);
}

static void listener_free(listener_t *l)
{
    ev_retire(&l->ev);
}

/* Create listeners for cfg, reusing sockets from the previous config.
 * Several sites may share one bind address; they are told apart by Host/SNI. */
static int apply_listeners(config_t *cfg, char *err, size_t errlen)
{
    listener_t *fresh = NULL;
    listener_t **tail = &fresh;
    for (int i = 0; i < cfg->nservers; i++) {
        server_t *s = cfg->servers[i];
        for (int a = 0; a < s->naddr; a++) {
            const char *addr = s->addrs[a];
            listener_t *l = NULL;
            for (listener_t *f = fresh; f; f = f->next)
                if (strcmp(f->addr, addr) == 0)
                    l = f;
            if (!l) {
                listener_t *old = find_listener(addr);
                int fd;
                if (old) {
                    fd = dup(old->ev.fd);
                    if (fd < 0) {
                        snprintf(err, errlen, "dup: %s", strerror(errno));
                        goto fail;
                    }
                    set_cloexec(fd);
                } else {
                    fd = bind_listener(addr, err, errlen);
                    if (fd < 0)
                        goto fail;
                }
                l = xcalloc(1, sizeof *l);
                l->ev.fd = fd;
                l->ev.cb = listener_cb;
                l->ev.destroy = listener_destroy;
                l->cfg = cfg;
                config_ref(cfg);
                l->addr = xstrdup(addr);
                l->tls = s->tls_mode != TLS_NONE;
                *tail = l;
                tail = &l->next;
            }
            if ((s->tls_mode != TLS_NONE) != l->tls) {
                snprintf(err, errlen, "address %s is used by both an http and an https site", addr);
                goto fail;
            }
            if (s->nhosts == 0) {
                for (int k = 0; k < l->nservers; k++)
                    if (l->servers[k]->nhosts == 0) {
                        snprintf(err, errlen, "address %s is used by more than one site without a hostname", addr);
                        goto fail;
                    }
                l->default_srv = s;
            }
            l->servers = xrealloc(l->servers, sizeof(server_t *) * (size_t)(l->nservers + 1));
            l->servers[l->nservers++] = s;
        }
    }
    for (listener_t *l = fresh; l; l = l->next)
        if (!l->default_srv)
            l->default_srv = l->servers[0];
    /* swap in */
    while (g_listeners) {
        listener_t *l = g_listeners;
        g_listeners = l->next;
        listener_free(l);
    }
    g_listeners = fresh;
    for (listener_t *l = g_listeners; l; l = l->next) {
        if (ev_add(&l->ev, EPOLLIN) < 0) {
            snprintf(err, errlen, "epoll_ctl: %s", strerror(errno));
            return -1;
        }
        buf_t names;
        buf_init(&names);
        for (int k = 0; k < l->nservers; k++) {
            server_t *s = l->servers[k];
            if (k)
                buf_puts(&names, ", ");
            if (s->is_admin)
                buf_puts(&names, "admin");
            else if (s->nhosts)
                buf_printf(&names, "%s%s", s->hosts[0], s->nhosts > 1 ? "+" : "");
            else
                buf_puts(&names, "*");
            if (s->redirect_https)
                buf_puts(&names, " (redirect)");
        }
        buf_append(&names, "", 1);
        LOGI("listening on %s%s: %s", l->addr, l->tls ? " (tls)" : "", names.data);
        buf_free(&names);
    }
    return 0;
fail:
    while (fresh) {
        listener_t *l = fresh;
        fresh = l->next;
        listener_free(l);
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Active health checks                                                */
/* ------------------------------------------------------------------ */

static void hc_destroy(ev_t *e)
{
    hc_conn_t *h = (hc_conn_t *)e;
    buf_free(&h->rbuf);
    buf_free(&h->wbuf);
    config_unref(h->cfg);
    free(h);
}

static void hc_close(hc_conn_t *h)
{
    if (h->ev.fd < 0)
        return;
    if (h->up->hc == h)
        h->up->hc = NULL;
    ev_retire(&h->ev);
}

static void hc_finish(hc_conn_t *h, int ok, const char *detail)
{
    upstream_t *u = h->up;
    pool_t *p = h->pool;
    int prev = u->hc_status;
    u->hc_status = ok ? 1 : -1;
    u->hc_last = g_now;
    u->hc_next = g_now + p->health_interval;
    snprintf(u->hc_detail, sizeof u->hc_detail, "%s", detail);
    if (prev != u->hc_status) {
        if (ok)
            LOGI("health check: upstream %s is up (%s)", u->hostport, detail);
        else
            LOGW("health check: upstream %s is DOWN (%s)", u->hostport, detail);
    }
    hc_close(h);
}

static void hc_cb(ev_t *e, uint32_t events)
{
    hc_conn_t *h = (hc_conn_t *)e;
    if (!h->connected) {
        int err = 0;
        socklen_t el = sizeof err;
        if (getsockopt(h->ev.fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0)
            err = errno;
        if (err) {
            char d[96];
            snprintf(d, sizeof d, "connect: %s", strerror(err));
            hc_finish(h, 0, d);
            return;
        }
        h->connected = 1;
    }
    if (events & EPOLLOUT || !h->connected) {
        int rc = fd_flush(h->ev.fd, &h->wbuf);
        if (rc < 0) {
            hc_finish(h, 0, "write failed");
            return;
        }
        ev_mod(&h->ev, EPOLLIN | EPOLLRDHUP | (rc == 0 ? EPOLLOUT : 0));
    }
    if (events & (EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
        ssize_t r = fd_read(h->ev.fd, &h->rbuf);
        if (r == -1)
            return;
        if (r == -2) {
            hc_finish(h, 0, "read error");
            return;
        }
        http_resp_t resp;
        http_resp_init(&resp);
        size_t consumed;
        int rc = http_parse_response_head(&resp, buf_rptr(&h->rbuf), buf_readable(&h->rbuf), &consumed);
        if (rc == 0) {
            if (r == 0)
                hc_finish(h, 0, "closed before response");
            else if (buf_readable(&h->rbuf) > HTTP_MAX_HEAD)
                hc_finish(h, 0, "response too large");
            return;
        }
        if (rc < 0) {
            hc_finish(h, 0, "malformed response");
            http_resp_free(&resp);
            return;
        }
        char d[64];
        snprintf(d, sizeof d, "status %d", resp.status);
        int ok = h->pool->health_status ? resp.status == h->pool->health_status
                                        : (resp.status >= 200 && resp.status < 400);
        http_resp_free(&resp);
        hc_finish(h, ok, d);
    }
}

static void hc_start(upstream_t *u, pool_t *p, config_t *cfg)
{
    int fd = socket(u->addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return;
    int rc = connect(fd, (struct sockaddr *)&u->addr, u->addrlen);
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        int prev = u->hc_status;
        u->hc_status = -1;
        u->hc_last = g_now;
        u->hc_next = g_now + p->health_interval;
        snprintf(u->hc_detail, sizeof u->hc_detail, "connect: %s", strerror(errno));
        if (prev != -1)
            LOGW("health check: upstream %s is DOWN (%s)", u->hostport, u->hc_detail);
        return;
    }
    hc_conn_t *h = xcalloc(1, sizeof *h);
    h->ev.fd = fd;
    h->ev.cb = hc_cb;
    h->ev.destroy = hc_destroy;
    h->up = u;
    h->pool = p;
    h->cfg = cfg;
    config_ref(cfg);
    h->connected = rc == 0;
    h->deadline = g_now + p->health_timeout;
    buf_init(&h->rbuf);
    buf_init(&h->wbuf);
    buf_printf(&h->wbuf, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: limer/%s (health check)\r\nConnection: close\r\n\r\n",
               p->health_uri, p->health_host ? p->health_host : u->hostport, LIMER_VERSION);
    u->hc = h;
    u->hc_next = g_now + p->health_interval; /* in case of timeouts */
    ev_add(&h->ev, EPOLLOUT | EPOLLIN | EPOLLRDHUP);
}

static void health_tick(void)
{
    if (!g_cfg || g_shutting_down)
        return;
    for (int i = 0; i < g_cfg->nservers; i++) {
        server_t *s = g_cfg->servers[i];
        for (int r = 0; r < s->nroutes; r++) {
            pool_t *p = s->routes[r]->pool;
            if (!p || !p->health_uri)
                continue;
            for (int k = 0; k < p->nups; k++) {
                upstream_t *u = p->ups[k];
                if (u->hc) {
                    if (g_now > u->hc->deadline)
                        hc_finish(u->hc, 0, "timeout");
                    continue;
                }
                if (g_now >= u->hc_next)
                    hc_start(u, p, g_cfg);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Static files                                                        */
/* ------------------------------------------------------------------ */

#define FILE_CHUNK (64 * 1024)

static void file_pump(conn_t *c)
{
    for (;;) {
        while (c->file_remaining > 0 && buf_readable(&c->wbuf) < WBUF_HIGH_WATER) {
            char tmp[FILE_CHUNK];
            size_t want = c->file_remaining < (off_t)sizeof tmp ? (size_t)c->file_remaining : sizeof tmp;
            ssize_t r = pread(c->file_fd, tmp, want, c->file_off);
            if (r <= 0) {
                LOGW("file read failed: %s", r < 0 ? strerror(errno) : "short file");
                c->close_after_write = 1;
                c->file_remaining = 0;
                break;
            }
            c->file_off += r;
            c->file_remaining -= r;
            conn_body_emit(c, tmp, (size_t)r, 0);
        }
        if (c->file_remaining == 0) {
            conn_body_finish(c);
            close(c->file_fd);
            c->file_fd = -1;
            conn_next_request(c);
            return;
        }
        conn_flush(c);
        if (c->dead)
            return;
        if (buf_readable(&c->wbuf) > 0) {
            conn_update_mask(c); /* resume on EPOLLOUT */
            return;
        }
    }
}

/* Parse a single-range "bytes=a-b" header. Returns 0 full, 1 partial, -1 unsatisfiable, 2 ignore. */
static int parse_range(const char *v, off_t size, off_t *start, off_t *end)
{
    if (!v || strncasecmp(v, "bytes=", 6) != 0)
        return 0;
    v += 6;
    if (strchr(v, ','))
        return 2; /* multiple ranges are served in full */
    char *dash = strchr(v, '-');
    if (!dash)
        return -1;
    if (dash == v) {
        /* suffix: last N bytes */
        long long n = atoll(dash + 1);
        if (n <= 0)
            return -1;
        if (n > size)
            n = size;
        *start = size - n;
        *end = size - 1;
    } else {
        char *e1;
        long long a = strtoll(v, &e1, 10);
        if (e1 != dash || a < 0)
            return -1;
        long long b = size - 1;
        if (dash[1]) {
            char *e2;
            b = strtoll(dash + 1, &e2, 10);
            if (*e2 || b < a)
                return -1;
            if (b > size - 1)
                b = size - 1;
        }
        if (a > size - 1)
            return -1;
        *start = a;
        *end = b;
    }
    return 1;
}

static void conn_serve_files(conn_t *c, route_t *r)
{
    file_server_t *fs = r->files;
    http_req_t *q = &c->req;
    int is_head = strcmp(q->method, "HEAD") == 0;
    if (!is_head && strcmp(q->method, "GET") != 0) {
        conn_write_simple_response(c, 405, "text/plain; charset=utf-8", "405 Method Not Allowed\n", 23, NULL, 0, "Allow: GET, HEAD\r\n");
        c->state = CS_LOCAL;
        conn_next_request(c);
        return;
    }
    char *clean = path_clean(q->path);
    if (!clean || (fs->hide_dotfiles && path_has_dotfile(clean))) {
        free(clean);
        conn_send_error(c, 404, "not found", 0);
        return;
    }
    /* try_files: first existing candidate wins */
    if (fs->ntry) {
        for (int i = 0; i < fs->ntry; i++) {
            buf_t cand;
            buf_init(&cand);
            expand_placeholders(fs->try_files[i], c, &cand);
            buf_append(&cand, "", 1);
            char *cc = path_clean(cand.data);
            buf_free(&cand);
            if (!cc)
                continue;
            char full[4096];
            snprintf(full, sizeof full, "%s%s", fs->root, cc);
            struct stat st;
            if (stat(full, &st) == 0 && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))) {
                free(clean);
                clean = cc;
                break;
            }
            free(cc);
        }
    }
    char full[4096];
    snprintf(full, sizeof full, "%s%s", fs->root, clean);
    struct stat st;
    if (stat(full, &st) < 0) {
        free(clean);
        conn_send_error(c, errno == EACCES ? 403 : 404, errno == EACCES ? "forbidden" : "not found", 0);
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        size_t cl = strlen(clean);
        if (clean[cl - 1] != '/') {
            char loc[4096];
            const char *shown = q->orig_path ? q->orig_path : q->path;
            snprintf(loc, sizeof loc, "Location: %s/%s%s\r\n", shown, *q->query ? "?" : "", q->query);
            free(clean);
            conn_write_simple_response(c, 301, "text/plain; charset=utf-8", "", 0, r->hdr_down, r->n_hdr_down, loc);
            c->state = CS_LOCAL;
            conn_next_request(c);
            return;
        }
        int found = 0;
        for (int i = 0; i < fs->nindex; i++) {
            char cand[4096];
            snprintf(cand, sizeof cand, "%s%s", full, fs->index[i]);
            struct stat ist;
            if (stat(cand, &ist) == 0 && S_ISREG(ist.st_mode)) {
                snprintf(full, sizeof full, "%s", cand);
                st = ist;
                found = 1;
                break;
            }
        }
        if (!found) {
            if (!fs->browse) {
                free(clean);
                conn_send_error(c, 404, "not found", 0);
                return;
            }
            buf_t html;
            buf_init(&html);
            if (files_listing(full, clean, fs->hide_dotfiles, &html) < 0) {
                buf_free(&html);
                free(clean);
                conn_send_error(c, 403, "forbidden", 0);
                return;
            }
            conn_write_simple_response(c, 200, "text/html; charset=utf-8", html.data ? html.data : "", html.len, r->hdr_down, r->n_hdr_down, NULL);
            buf_free(&html);
            free(clean);
            c->state = CS_LOCAL;
            conn_next_request(c);
            return;
        }
    }
    free(clean);
    if (!S_ISREG(st.st_mode)) {
        conn_send_error(c, 404, "not found", 0);
        return;
    }
    int fd = open(full, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        conn_send_error(c, errno == EACCES ? 403 : 404, errno == EACCES ? "forbidden" : "not found", 0);
        return;
    }
    char etag[64], lastmod[64];
    snprintf(etag, sizeof etag, "\"%llx-%llx\"", (unsigned long long)st.st_mtime, (unsigned long long)st.st_size);
    http_date(st.st_mtime, lastmod, sizeof lastmod);

    /* conditional requests */
    const char *inm = http_hdr_get(q->hdrs, q->nhdr, "If-None-Match");
    const char *ims = http_hdr_get(q->hdrs, q->nhdr, "If-Modified-Since");
    int not_modified = 0;
    if (inm) {
        not_modified = strstr(inm, etag) != NULL || strcmp(inm, "*") == 0;
    } else if (ims) {
        time_t t = http_date_parse(ims);
        if (t != (time_t)-1 && st.st_mtime <= t)
            not_modified = 1;
    }
    const char *ctype = mime_type_for(full);
    int status = 200;
    off_t start = 0, end = st.st_size - 1;
    char extra[512] = "";
    if (not_modified) {
        close(fd);
        snprintf(extra, sizeof extra, "ETag: %s\r\nLast-Modified: %s\r\n", etag, lastmod);
        conn_write_simple_response(c, 304, NULL, "", 0, r->hdr_down, r->n_hdr_down, extra);
        c->state = CS_LOCAL;
        conn_next_request(c);
        return;
    }
    const char *range = http_hdr_get(q->hdrs, q->nhdr, "Range");
    const char *ifrange = http_hdr_get(q->hdrs, q->nhdr, "If-Range");
    if (range && ifrange && strcmp(ifrange, etag) != 0)
        range = NULL;
    if (range && st.st_size > 0) {
        int rr = parse_range(range, st.st_size, &start, &end);
        if (rr < 0) {
            close(fd);
            snprintf(extra, sizeof extra, "Content-Range: bytes */%lld\r\n", (long long)st.st_size);
            conn_write_simple_response(c, 416, "text/plain; charset=utf-8", "416 Range Not Satisfiable\n", 26, r->hdr_down, r->n_hdr_down, extra);
            c->state = CS_LOCAL;
            conn_next_request(c);
            return;
        }
        if (rr == 1)
            status = 206;
    }
    off_t length = end - start + 1;
    if (st.st_size == 0)
        length = 0;

    hlist_t h = { 0 };
    char tmp[128];
    hlist_add(&h, "Content-Type", ctype);
    hlist_add(&h, "Accept-Ranges", "bytes");
    hlist_add(&h, "ETag", etag);
    hlist_add(&h, "Last-Modified", lastmod);
    const char *encname = status == 200 ? conn_pick_encoding(c, ctype, (int64_t)length, 200, NULL) : NULL;
    if (encname && !is_head && (c->enc = encoder_new(encname)) != NULL) {
        hlist_add(&h, "Content-Encoding", encname);
        hlist_add(&h, "Vary", "Accept-Encoding");
        if (c->req.minor >= 1) {
            c->out_chunked = 1;
            hlist_add(&h, "Transfer-Encoding", "chunked");
        } else {
            c->close_after_write = 1;
        }
    } else {
        snprintf(tmp, sizeof tmp, "%lld", (long long)length);
        hlist_add(&h, "Content-Length", tmp);
        if (status == 206) {
            snprintf(tmp, sizeof tmp, "bytes %lld-%lld/%lld", (long long)start, (long long)end, (long long)st.st_size);
            hlist_add(&h, "Content-Range", tmp);
        }
    }
    int keep = q->keep_alive && !g_shutting_down && !c->close_after_write;
    hlist_add(&h, "Connection", keep ? "keep-alive" : "close");
    if (c->srv->n_hdr_down)
        hlist_apply_ops(&h, c->srv->hdr_down, c->srv->n_hdr_down, c);
    hlist_apply_ops(&h, r->hdr_down, r->n_hdr_down, c);
    buf_printf(&c->wbuf, "HTTP/1.1 %d %s\r\n", status, http_status_reason(status));
    hlist_write(&h, &c->wbuf);
    buf_puts(&c->wbuf, "\r\n");
    hlist_free(&h);
    c->resp_status = status;
    c->resp_head_sent = 1;
    if (!keep)
        c->close_after_write = 1;
    c->state = CS_LOCAL;
    if (is_head || length == 0) {
        close(fd);
        if (c->enc) {
            encoder_free(c->enc);
            c->enc = NULL;
        }
        if (c->out_chunked)
            conn_body_finish(c);
        conn_next_request(c);
        return;
    }
    c->file_fd = fd;
    c->file_off = start;
    c->file_remaining = length;
    file_pump(c);
}

/* ------------------------------------------------------------------ */
/* Admin API                                                           */
/* ------------------------------------------------------------------ */

static void json_escape(buf_t *b, const char *s)
{
    buf_append(b, "\"", 1);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')
            buf_printf(b, "\\%c", c);
        else if (c < 0x20)
            buf_printf(b, "\\u%04x", c);
        else
            buf_append(b, s, 1);
    }
    buf_append(b, "\"", 1);
}

static void admin_upstreams_json(buf_t *b)
{
    buf_puts(b, "{\"worker\":");
    buf_printf(b, "%d,\"pools\":[", g_worker_id);
    int first_pool = 1;
    for (int i = 0; i < g_cfg->nservers; i++) {
        server_t *s = g_cfg->servers[i];
        for (int r = 0; r < s->nroutes; r++) {
            pool_t *p = s->routes[r]->pool;
            if (!p)
                continue;
            if (!first_pool)
                buf_puts(b, ",");
            first_pool = 0;
            buf_puts(b, "{\"name\":");
            json_escape(b, p->name);
            buf_puts(b, ",\"listen\":");
            json_escape(b, s->addrs[0]);
            buf_printf(b, ",\"policy\":\"%s\"", lb_policy_name(p->policy));
            if (p->policy == LB_HASH) {
                buf_printf(b, ",\"hash_key\":{\"source\":\"%s\"", keysrc_name(p->key.src));
                if (p->key.name) {
                    buf_puts(b, ",\"name\":");
                    json_escape(b, p->key.name);
                }
                buf_puts(b, "}");
            }
            buf_puts(b, ",\"upstreams\":[");
            for (int k = 0; k < p->nups; k++) {
                upstream_t *u = p->ups[k];
                if (k)
                    buf_puts(b, ",");
                buf_puts(b, "{\"address\":");
                json_escape(b, u->hostport);
                buf_printf(b, ",\"weight\":%d,\"healthy\":%s,\"active_requests\":%d,\"idle_connections\":%d,"
                              "\"requests\":%llu,\"responses\":%llu,\"failures\":%llu,\"passive_down_for\":%.1f,"
                              "\"active_check\":",
                           u->weight, upstream_healthy(u, g_now) ? "true" : "false", u->active, u->nidle,
                           (unsigned long long)u->requests, (unsigned long long)u->responses,
                           (unsigned long long)u->failures,
                           u->fail_until > g_now ? u->fail_until - g_now : 0.0);
                if (!p->health_uri)
                    buf_puts(b, "\"disabled\"");
                else
                    json_escape(b, u->hc_status == 0 ? "pending" : u->hc_detail);
                buf_puts(b, "}");
            }
            buf_puts(b, "]}");
        }
    }
    buf_puts(b, "]}\n");
}

static void admin_metrics(buf_t *b)
{
    buf_puts(b, "# HELP limer_requests_total Requests received.\n# TYPE limer_requests_total counter\n");
    buf_printf(b, "limer_requests_total{worker=\"%d\"} %llu\n", g_worker_id, (unsigned long long)g_stats.requests);
    buf_puts(b, "# HELP limer_responses_total Responses sent by status class.\n# TYPE limer_responses_total counter\n");
    for (int i = 1; i <= 5; i++)
        buf_printf(b, "limer_responses_total{worker=\"%d\",class=\"%dxx\"} %llu\n", g_worker_id, i, (unsigned long long)g_stats.resp_class[i]);
    buf_puts(b, "# HELP limer_upstream_errors_total Failed upstream attempts.\n# TYPE limer_upstream_errors_total counter\n");
    buf_printf(b, "limer_upstream_errors_total{worker=\"%d\"} %llu\n", g_worker_id, (unsigned long long)g_stats.upstream_errors);
    buf_puts(b, "# HELP limer_retries_total Requests retried on another upstream.\n# TYPE limer_retries_total counter\n");
    buf_printf(b, "limer_retries_total{worker=\"%d\"} %llu\n", g_worker_id, (unsigned long long)g_stats.retries);
    buf_puts(b, "# HELP limer_connections_active Open client connections.\n# TYPE limer_connections_active gauge\n");
    buf_printf(b, "limer_connections_active{worker=\"%d\"} %d\n", g_worker_id, g_stats.active_conns);
    buf_puts(b, "# HELP limer_upstream_connections Open upstream connections (active + idle).\n# TYPE limer_upstream_connections gauge\n");
    buf_printf(b, "limer_upstream_connections{worker=\"%d\"} %d\n", g_worker_id, g_stats.active_uconns);
    buf_puts(b, "# HELP limer_upstream_healthy Whether an upstream is eligible for traffic.\n# TYPE limer_upstream_healthy gauge\n");
    buf_puts(b, "# HELP limer_upstream_requests_total Requests sent to an upstream.\n# TYPE limer_upstream_requests_total counter\n");
    buf_puts(b, "# HELP limer_upstream_failures_total Failures recorded for an upstream.\n# TYPE limer_upstream_failures_total counter\n");
    buf_puts(b, "# HELP limer_upstream_active_requests In-flight requests per upstream.\n# TYPE limer_upstream_active_requests gauge\n");
    for (int i = 0; i < g_cfg->nservers; i++) {
        server_t *s = g_cfg->servers[i];
        for (int r = 0; r < s->nroutes; r++) {
            pool_t *p = s->routes[r]->pool;
            if (!p)
                continue;
            for (int k = 0; k < p->nups; k++) {
                upstream_t *u = p->ups[k];
                buf_printf(b, "limer_upstream_healthy{worker=\"%d\",pool=\"%s\",upstream=\"%s\"} %d\n", g_worker_id, p->name, u->hostport, upstream_healthy(u, g_now));
                buf_printf(b, "limer_upstream_requests_total{worker=\"%d\",pool=\"%s\",upstream=\"%s\"} %llu\n", g_worker_id, p->name, u->hostport, (unsigned long long)u->requests);
                buf_printf(b, "limer_upstream_failures_total{worker=\"%d\",pool=\"%s\",upstream=\"%s\"} %llu\n", g_worker_id, p->name, u->hostport, (unsigned long long)u->failures);
                buf_printf(b, "limer_upstream_active_requests{worker=\"%d\",pool=\"%s\",upstream=\"%s\"} %d\n", g_worker_id, p->name, u->hostport, u->active);
            }
        }
    }
}

static int g_master_pid;

static void admin_handle(conn_t *c)
{
    const char *path = c->req.path;
    buf_t b;
    buf_init(&b);
    int status = 200;
    const char *ctype = "application/json";
    if (strcmp(path, "/") == 0 || strcmp(path, "/health") == 0 || strcmp(path, "/healthz") == 0) {
        buf_printf(&b, "{\"status\":\"ok\",\"version\":\"%s\",\"worker\":%d}\n", LIMER_VERSION, g_worker_id);
    } else if (strcmp(path, "/upstreams") == 0) {
        admin_upstreams_json(&b);
    } else if (strcmp(path, "/metrics") == 0) {
        ctype = "text/plain; version=0.0.4; charset=utf-8";
        admin_metrics(&b);
    } else if (strcmp(path, "/config") == 0) {
        ctype = "text/plain; charset=utf-8";
        buf_puts(&b, g_cfg->text);
    } else if (strcmp(path, "/reload") == 0) {
        if (strcmp(c->req.method, "POST") != 0) {
            status = 405;
            buf_puts(&b, "{\"error\":\"use POST\"}\n");
        } else {
            if (g_master_pid > 0)
                kill(g_master_pid, SIGHUP);
            else
                proxy_request_reload();
            buf_puts(&b, "{\"status\":\"reload scheduled\"}\n");
        }
    } else {
        status = 404;
        buf_puts(&b, "{\"error\":\"not found\",\"endpoints\":[\"/health\",\"/upstreams\",\"/metrics\",\"/config\",\"/reload (POST)\"]}\n");
    }
    c->route = NULL;
    conn_write_simple_response(c, status, ctype, b.data ? b.data : "", b.len, NULL, 0, NULL);
    buf_free(&b);
    c->state = CS_LOCAL;
    conn_next_request(c);
}

/* ------------------------------------------------------------------ */
/* Timers, reload, shutdown                                            */
/* ------------------------------------------------------------------ */

static void retire_config(config_t *old)
{
    /* close idle upstream connections and health checks that belong to the old config */
    uconn_t *uc = g_uconns;
    while (uc) {
        uconn_t *next = uc->next;
        if (uc->cfg == old && uc->state == US_IDLE)
            uconn_close(uc);
        uc = next;
    }
    for (int i = 0; i < old->nservers; i++) {
        server_t *s = old->servers[i];
        for (int r = 0; r < s->nroutes; r++) {
            pool_t *p = s->routes[r]->pool;
            if (!p)
                continue;
            for (int k = 0; k < p->nups; k++)
                if (p->ups[k]->hc)
                    hc_close(p->ups[k]->hc);
        }
    }
    config_unref(old);
}

/* Carry runtime health state over to upstreams with the same address. */
static void inherit_state(config_t *old, config_t *cfg)
{
    for (int i = 0; i < cfg->nservers; i++) {
        server_t *s = cfg->servers[i];
        for (int r = 0; r < s->nroutes; r++) {
            pool_t *p = s->routes[r]->pool;
            if (!p)
                continue;
            for (int k = 0; k < p->nups; k++) {
                upstream_t *u = p->ups[k];
                for (int oi = 0; oi < old->nservers; oi++) {
                    server_t *os = old->servers[oi];
                    for (int orr = 0; orr < os->nroutes; orr++) {
                        pool_t *op = os->routes[orr]->pool;
                        if (!op || strcmp(op->name, p->name) != 0)
                            continue;
                        for (int ok = 0; ok < op->nups; ok++) {
                            upstream_t *ou = op->ups[ok];
                            if (strcmp(ou->hostport, u->hostport) == 0) {
                                u->hc_status = p->health_uri ? ou->hc_status : 0;
                                u->hc_last = ou->hc_last;
                                u->hc_next = ou->hc_next;
                                u->fails = ou->fails;
                                u->fail_until = ou->fail_until;
                                memcpy(u->hc_detail, ou->hc_detail, sizeof u->hc_detail);
                            }
                        }
                    }
                }
            }
        }
    }
}

static void do_reload(void)
{
    char err[512];
    LOGI("reloading configuration from %s", g_cfg->path);
    config_t *cfg = config_load(g_cfg->path, err, sizeof err);
    if (!cfg) {
        LOGE("reload failed, keeping current configuration: %s", err);
        return;
    }
    if (apply_listeners(cfg, err, sizeof err) < 0) {
        LOGE("reload failed, keeping current configuration: %s", err);
        config_unref(cfg);
        return;
    }
    log_level = cfg->log_level;
    inherit_state(g_cfg, cfg);
    config_t *old = g_cfg;
    g_cfg = cfg;
    retire_config(old);
    if (g_worker_id == 0) {
        acme_manager_stop();
        acme_manager_start(cfg);
    }
    LOGI("configuration reloaded");
}

static void begin_shutdown(void)
{
    if (g_shutting_down)
        return;
    g_shutting_down = 1;
    g_shutdown_deadline = g_now + g_cfg->grace;
    LOGI("shutting down: waiting up to %.0fs for %d connection(s)", g_cfg->grace, g_stats.active_conns);
    while (g_listeners) {
        listener_t *l = g_listeners;
        g_listeners = l->next;
        listener_free(l);
    }
    /* drop idle keep-alive clients and idle upstream connections right away */
    conn_t *c = g_conns;
    while (c) {
        conn_t *next = c->next;
        if (c->state == CS_HEAD && !c->got_request_bytes)
            conn_close(c);
        c = next;
    }
    uconn_t *uc = g_uconns;
    while (uc) {
        uconn_t *next = uc->next;
        if (uc->state == US_IDLE)
            uconn_close(uc);
        uc = next;
    }
}

static void tick(void)
{
    g_now = now_mono();
    if (g_worker_id == 0) {
        /* reap the certificate manager if it exited; restart it later via reload */
        int status;
        pid_t p;
        while ((p = waitpid(-1, &status, WNOHANG)) > 0)
            LOGW("child process %d exited unexpectedly", (int)p);
    }
    if (g_reload_flag) {
        g_reload_flag = 0;
        do_reload();
    }
    if (g_shutdown_flag && !g_shutting_down)
        begin_shutdown();

    /* client timeouts */
    conn_t *c = g_conns;
    while (c) {
        conn_t *next = c->next;
        if (!c->dead && c->deadline > 0 && g_now > c->deadline) {
            switch (c->state) {
            case CS_HEAD:
                if (c->got_request_bytes)
                    conn_send_error(c, 408, "request timeout", 1);
                else
                    conn_close(c); /* idle keep-alive */
                break;
            case CS_BODY:
                conn_send_error(c, 408, "request body timeout", 1);
                break;
            case CS_UPSTREAM:
                if (c->uc) {
                    uconn_t *uc = c->uc;
                    int connecting = uc->state == US_CONNECTING;
                    uconn_fail(uc, connecting ? "connect timeout" : "response timeout", 504,
                               connecting || (!uc->got_bytes && (uc->reused || method_idempotent(c->req.method))));
                } else {
                    conn_send_error(c, 504, "upstream timeout", 0);
                }
                break;
            default:
                conn_close(c);
                break;
            }
        }
        c = next;
    }

    /* idle upstream connection expiry */
    uconn_t *uc = g_uconns;
    while (uc) {
        uconn_t *next = uc->next;
        if (!uc->dead && uc->state == US_IDLE && g_now - uc->idle_since > uc->pool->keepalive_timeout)
            uconn_close(uc);
        uc = next;
    }

    for (listener_t *l = g_listeners; l; l = l->next)
        if (l->paused_until > 0 && g_now >= l->paused_until) {
            l->paused_until = 0;
            ev_mod(&l->ev, EPOLLIN);
        }

    health_tick();
    reap_graveyard();
}

static void timer_cb(ev_t *e, uint32_t events)
{
    uint64_t exp;
    (void)!read(e->fd, &exp, sizeof exp);
    tick();
}

static void on_sighup(int sig)  { (void)sig; g_reload_flag = 1; }
static void on_sigterm(int sig) { (void)sig; g_shutdown_flag = 1; }

void proxy_request_reload(void)   { g_reload_flag = 1; }
void proxy_request_shutdown(void) { g_shutdown_flag = 1; }

int proxy_run(config_t *cfg, int worker_id)
{
    char err[512];
    g_worker_id = worker_id;
    g_master_pid = worker_id > 0 ? (int)getppid() : 0;
    g_cfg = cfg;
    g_now = now_mono();
    srand((unsigned)(getpid() ^ (unsigned)(g_now * 1000)));
    log_level = cfg->log_level;

    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0) {
        LOGE("epoll_create1: %s", strerror(errno));
        return 1;
    }

    /* Raise the descriptor limit as far as allowed; every proxied request
     * needs two descriptors, so derive a default connection cap from it. */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        if (rl.rlim_cur < rl.rlim_max) {
            rl.rlim_cur = rl.rlim_max;
            if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
                getrlimit(RLIMIT_NOFILE, &rl);
        }
        if (cfg->max_connections == 0 && rl.rlim_cur != RLIM_INFINITY) {
            long cap = ((long)rl.rlim_cur - 64) / 2;
            cfg->max_connections = cap < 64 ? 64 : (int)(cap > 1000000 ? 1000000 : cap);
        }
        LOGI("descriptor limit %lu, max_connections %d", (unsigned long)rl.rlim_cur, cfg->max_connections);
    }
    signal(SIGPIPE, SIG_IGN);
#ifdef LIMER_TLS
    tls_set_sni_resolver(sni_resolve);
#endif
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sighup;
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = on_sigterm;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    if (apply_listeners(cfg, err, sizeof err) < 0) {
        LOGE("%s", err);
        return 1;
    }

    if (worker_id == 0)
        acme_manager_start(cfg);

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    struct itimerspec its;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = TICK_MS * 1000000L;
    its.it_value = its.it_interval;
    timerfd_settime(tfd, 0, &its, NULL);
    g_timer_ev.fd = tfd;
    g_timer_ev.cb = timer_cb;
    ev_add(&g_timer_ev, EPOLLIN);

    LOGI("limer %s worker %d ready (%d server block%s)", LIMER_VERSION, worker_id, cfg->nservers, cfg->nservers == 1 ? "" : "s");

    struct epoll_event evs[256];
    for (;;) {
        if (g_shutting_down && (g_stats.active_conns == 0 || g_now > g_shutdown_deadline)) {
            if (g_stats.active_conns > 0)
                LOGW("grace period over, dropping %d connection(s)", g_stats.active_conns);
            break;
        }
        int n = epoll_wait(g_epfd, evs, 256, TICK_MS);
        if (n < 0) {
            if (errno == EINTR) {
                tick();
                continue;
            }
            LOGE("epoll_wait: %s", strerror(errno));
            return 1;
        }
        g_now = now_mono();
        for (int i = 0; i < n; i++) {
            ev_t *e = evs[i].data.ptr;
            if (e->fd < 0)
                continue; /* closed earlier in this batch */
            e->cb(e, evs[i].events);
        }
        reap_graveyard();
    }

    /* teardown */
    if (worker_id == 0)
        acme_manager_stop();
    while (g_conns)
        conn_close(g_conns);
    while (g_uconns)
        uconn_close(g_uconns);
    reap_graveyard();
    while (g_listeners) {
        listener_t *l = g_listeners;
        g_listeners = l->next;
        listener_free(l);
    }
    for (int i = 0; i < g_cfg->nservers; i++) {
        server_t *s = g_cfg->servers[i];
        for (int r = 0; r < s->nroutes; r++) {
            pool_t *p = s->routes[r]->pool;
            if (!p)
                continue;
            for (int k = 0; k < p->nups; k++)
                if (p->ups[k]->hc)
                    hc_close(p->ups[k]->hc);
        }
    }
    reap_graveyard();
    ev_del(&g_timer_ev);
    close(tfd);
    close(g_epfd);
    g_epfd = -1;
    config_unref(g_cfg);
    g_cfg = NULL;
    LOGI("worker %d stopped", worker_id);
    return 0;
}
