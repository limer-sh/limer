/*
 * h2u.inc - HTTP/2 to upstreams (included by proxy.c, requires nghttp2).
 *
 * An upstream marked h2 (h2c:// or transport versions h2/h2c) is reached
 * through multiplexed HTTP/2 sessions. Each client request gets a pseudo
 * uconn_t (no socket) attached to a session: the HTTP/1.1 request that
 * build_upstream_request() produced is parsed back into HEADERS + DATA, and
 * the response frames are written into the pseudo uconn's rbuf as a chunked
 * HTTP/1.1 response (trailers included), so uconn_on_response_data() and
 * everything after it work unchanged. Flow-control windows are only
 * released as the client consumes the data.
 */

#define H2U_MAX_STREAMS 100
#define H2U_WINDOW      (256 * 1024)

typedef struct h2u_session {
    ev_t ev;
    upstream_t *up;
    pool_t *pool;
    config_t *cfg;
    int state;                  /* 0 connecting, 1 tls handshake, 2 active, 3 closing */
#ifdef LIMER_TLS
    SSL *ssl;
#endif
    nghttp2_session *ng;
    buf_t rbuf, wbuf;
    uconn_t **streams;
    int nstreams, cap;
    int in_callback;
    int sending;
    int dead;
    double idle_since;
    struct h2u_session *next;   /* global list */
} h2u_session_t;

static h2u_session_t *g_h2u_sessions;

static void h2u_session_send(h2u_session_t *s);
static void h2u_session_fail(h2u_session_t *s, const char *reason);
static void h2u_submit(uconn_t *uc);

static void h2u_streams_add(h2u_session_t *s, uconn_t *uc)
{
    if (s->nstreams == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 16;
        s->streams = xrealloc(s->streams, sizeof(uconn_t *) * (size_t)s->cap);
    }
    s->streams[s->nstreams++] = uc;
}

static void h2u_streams_del(h2u_session_t *s, uconn_t *uc)
{
    for (int i = 0; i < s->nstreams; i++)
        if (s->streams[i] == uc) {
            s->streams[i] = s->streams[--s->nstreams];
            break;
        }
    if (s->nstreams == 0)
        s->idle_since = g_now;
}

/* ---- response assembly into uc->rbuf as chunked HTTP/1.1 ---- */

static int h2u_on_begin_headers(nghttp2_session *ng, const nghttp2_frame *frame, void *user_data)
{
    (void)user_data;
    if (frame->hd.type != NGHTTP2_HEADERS)
        return 0;
    uconn_t *uc = nghttp2_session_get_stream_user_data(ng, frame->hd.stream_id);
    if (!uc)
        return 0;
    uc->h2u_skip = 0;
    if (frame->headers.cat == NGHTTP2_HCAT_HEADERS && uc->h2u_head_done && !uc->h2u_trailers) {
        /* trailers: start the chunked trailer section */
        buf_puts(&uc->rbuf, "0\r\n");
        uc->h2u_trailers = 1;
    }
    return 0;
}

static int h2u_on_header(nghttp2_session *ng, const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
                         const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    (void)flags; (void)user_data;
    if (frame->hd.type != NGHTTP2_HEADERS)
        return 0;
    uconn_t *uc = nghttp2_session_get_stream_user_data(ng, frame->hd.stream_id);
    if (!uc || uc->h2u_skip)
        return 0;
    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        int status = atoi((const char *)value);
        if (status < 200) {
            uc->h2u_skip = 1; /* interim response: ignore this block */
            return 0;
        }
        buf_printf(&uc->rbuf, "HTTP/1.1 %.*s %s\r\n", (int)valuelen, value, http_status_reason(status));
        return 0;
    }
    if (namelen && name[0] == ':')
        return 0;
    if (namelen == 14 && memcmp(name, "content-length", 14) == 0)
        return 0; /* the body is re-framed as chunked */
    buf_append(&uc->rbuf, name, namelen);
    buf_puts(&uc->rbuf, ": ");
    buf_append(&uc->rbuf, value, valuelen);
    buf_puts(&uc->rbuf, "\r\n");
    return 0;
}

static int h2u_on_frame_recv(nghttp2_session *ng, const nghttp2_frame *frame, void *user_data)
{
    (void)user_data;
    uconn_t *uc = nghttp2_session_get_stream_user_data(ng, frame->hd.stream_id);
    if (!uc)
        return 0;
    if (frame->hd.type == NGHTTP2_HEADERS) {
        if (uc->h2u_skip) {
            uc->h2u_skip = 0;
            return 0;
        }
        if (!uc->h2u_head_done) {
            buf_puts(&uc->rbuf, "Transfer-Encoding: chunked\r\n\r\n");
            uc->h2u_head_done = 1;
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
                buf_puts(&uc->rbuf, "0\r\n\r\n");
        } else if (uc->h2u_trailers) {
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
                buf_puts(&uc->rbuf, "\r\n");
        }
        uc->h2u_dirty = 1;
    } else if (frame->hd.type == NGHTTP2_DATA) {
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            buf_puts(&uc->rbuf, "0\r\n\r\n");
            uc->h2u_dirty = 1;
        }
    }
    return 0;
}

static int h2u_on_data_chunk(nghttp2_session *ng, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    (void)flags; (void)user_data;
    uconn_t *uc = nghttp2_session_get_stream_user_data(ng, stream_id);
    if (!uc)
        return 0;
    buf_printf(&uc->rbuf, "%zx\r\n", len);
    buf_append(&uc->rbuf, data, len);
    buf_puts(&uc->rbuf, "\r\n");
    uc->h2u_unconsumed += len;
    uc->h2u_dirty = 1;
    uc->got_bytes = 1;
    return 0;
}

static int h2u_on_stream_close(nghttp2_session *ng, int32_t stream_id, uint32_t error_code, void *user_data)
{
    h2u_session_t *s = user_data;
    uconn_t *uc = nghttp2_session_get_stream_user_data(ng, stream_id);
    if (!uc)
        return 0;
    nghttp2_session_set_stream_user_data(ng, stream_id, NULL);
    uc->h2u_stream_open = 0;
    if (error_code != NGHTTP2_NO_ERROR) {
        /* reset by the upstream: pretend the connection closed so the normal
         * failure path (retry or 502 / truncation) handles it */
        uc->h2u_failed = 1;
        uc->h2u_dirty = 1;
    }
    (void)s;
    return 0;
}

/* ---- request submission ---- */

static ssize_t h2u_req_read(nghttp2_session *ng, int32_t stream_id, uint8_t *buf, size_t length,
                            uint32_t *flags, nghttp2_data_source *source, void *user_data)
{
    (void)ng; (void)stream_id; (void)user_data;
    uconn_t *uc = source->ptr;
    size_t n = buf_readable(&uc->wbuf);
    if (n > length)
        n = length;
    if (n)
        memcpy(buf, buf_rptr(&uc->wbuf), n);
    buf_consume(&uc->wbuf, n);
    if (buf_readable(&uc->wbuf) == 0) {
        if (uc->req_eof) {
            *flags |= NGHTTP2_DATA_FLAG_EOF;
        } else if (n == 0) {
            uc->h2u_req_deferred = 1; /* resumed when more of the streamed body arrives */
            return NGHTTP2_ERR_DEFERRED;
        }
    }
    if (!uc->req_eof && uc->c && buf_readable(&uc->wbuf) < WBUF_LOW_WATER)
        uc->h2u_want_pump = 1; /* room for more: pull from the client after this send */
    return (ssize_t)n;
}

/* More streamed request-body bytes (or its end) were appended to uc->wbuf. */
static void h2u_body_resume(uconn_t *uc)
{
    h2u_session_t *s = uc->h2u;
    if (!s || s->dead || !s->ng || !uc->h2u_submitted || uc->dead)
        return;
    if (uc->h2u_req_deferred) {
        uc->h2u_req_deferred = 0;
        nghttp2_session_resume_data(s->ng, uc->h2u_stream_id);
    }
    if (!s->in_callback)
        h2u_session_send(s);
}

static void h2u_submit(uconn_t *uc)
{
    h2u_session_t *s = uc->h2u;
    if (!s || s->state != 2 || uc->h2u_submitted || uc->dead)
        return;
    http_req_t req;
    http_req_init(&req);
    size_t consumed = 0;
    int rc = http_parse_request_head(&req, buf_rptr(&uc->wbuf), buf_readable(&uc->wbuf), &consumed);
    if (rc != 1) {
        http_req_free(&req);
        uconn_fail(uc, "cannot build HTTP/2 request", 502, 0);
        return;
    }
    buf_consume(&uc->wbuf, consumed);
    nghttp2_nv *nva = xcalloc((size_t)req.nhdr + 6, sizeof(nghttp2_nv));
    int n = 0;
#define NV(k, v, vl) do { nva[n].name = (uint8_t *)(k); nva[n].namelen = strlen(k); nva[n].value = (uint8_t *)(v); nva[n].valuelen = (vl); nva[n].flags = NGHTTP2_NV_FLAG_NONE; n++; } while (0)
    NV(":method", req.method, strlen(req.method));
    NV(":scheme", uc->up->tls ? "https" : "http", uc->up->tls ? 5 : 4);
    const char *host = http_hdr_get(req.hdrs, req.nhdr, "Host");
    NV(":authority", host ? host : uc->up->hostport, strlen(host ? host : uc->up->hostport));
    NV(":path", req.uri, strlen(req.uri));
    const char *client_te = uc->c ? http_hdr_get(uc->c->req.hdrs, uc->c->req.nhdr, "TE") : NULL;
    for (int i = 0; i < req.nhdr; i++) {
        const char *nm = req.hdrs[i].name;
        if (strcasecmp(nm, "Host") == 0 || http_hdr_is_hop_by_hop(nm) || strcasecmp(nm, "Keep-Alive") == 0)
            continue;
        h2_lower(req.hdrs[i].name);
        NV(req.hdrs[i].name, req.hdrs[i].value, strlen(req.hdrs[i].value));
    }
    if (client_te && strcasecmp(client_te, "trailers") == 0)
        NV("te", "trailers", 8);
#undef NV
    nghttp2_data_provider prd;
    prd.source.ptr = uc;
    prd.read_callback = h2u_req_read;
    int has_body = buf_readable(&uc->wbuf) > 0 || !uc->req_eof;
    int32_t id = nghttp2_submit_request(s->ng, NULL, nva, (size_t)n, has_body ? &prd : NULL, uc);
    free(nva);
    http_req_free(&req);
    if (id < 0) {
        uconn_fail(uc, nghttp2_strerror(id), 502, 1);
        return;
    }
    uc->h2u_stream_id = id;
    uc->h2u_submitted = 1;
    uc->h2u_stream_open = 1;
    uc->connected = 1;
    if (uc->c)
        uc->c->deadline = g_now + s->pool->response_timeout;
    if (!s->in_callback)
        h2u_session_send(s);
}

/* ---- session lifecycle ---- */

static void h2u_session_destroy(ev_t *e)
{
    h2u_session_t *s = (h2u_session_t *)e;
#ifdef LIMER_TLS
    if (s->ssl)
        SSL_free(s->ssl);
#endif
    if (s->ng)
        nghttp2_session_del(s->ng);
    buf_free(&s->rbuf);
    buf_free(&s->wbuf);
    free(s->streams);
    config_unref(s->cfg);
    free(s);
}

static void h2u_session_close(h2u_session_t *s)
{
    if (s->dead)
        return;
    s->dead = 1;
    s->state = 3;
    /* unlink from the global and per-upstream lists */
    h2u_session_t **pp = &g_h2u_sessions;
    while (*pp && *pp != s)
        pp = &(*pp)->next;
    if (*pp)
        *pp = s->next;
    if (s->up->h2u == s) {
        s->up->h2u = NULL;
    }
    ev_retire(&s->ev);
}

/* Fail every stream on the session (retryable when nothing was received). */
static void h2u_session_fail(h2u_session_t *s, const char *reason)
{
    if (s->dead)
        return;
    s->state = 3;
    while (s->nstreams > 0) {
        uconn_t *uc = s->streams[s->nstreams - 1];
        h2u_streams_del(s, uc);
        uc->h2u = NULL;
        uconn_fail(uc, reason, 502, !uc->got_bytes);
    }
    h2u_session_close(s);
}

static void h2u_session_send(h2u_session_t *s)
{
    if (s->dead || s->state != 2 || s->sending)
        return;
    s->sending = 1;
    for (int round = 0; round < 4; round++) {
        for (;;) {
            const uint8_t *data;
            ssize_t n = nghttp2_session_mem_send(s->ng, &data);
            if (n <= 0)
                break;
            buf_append(&s->wbuf, data, (size_t)n);
            if (buf_readable(&s->wbuf) > WBUF_HIGH_WATER)
                break;
        }
        int rc;
#ifdef LIMER_TLS
        rc = s->ssl ? ssl_flush(s->ssl, &s->wbuf) : fd_flush(s->ev.fd, &s->wbuf);
#else
        rc = fd_flush(s->ev.fd, &s->wbuf);
#endif
        if (rc < 0) {
            s->sending = 0;
            h2u_session_fail(s, "HTTP/2 upstream write failed");
            return;
        }
        ev_mod(&s->ev, EPOLLIN | EPOLLRDHUP | (buf_readable(&s->wbuf) ? EPOLLOUT : 0));
        /* streams whose request body drained can take more from their clients */
        int pumped = 0;
        for (int i = 0; i < s->nstreams; i++) {
            uconn_t *uc = s->streams[i];
            if (!uc->h2u_want_pump)
                continue;
            uc->h2u_want_pump = 0;
            if (uc->c && !uc->dead && uc->c->body_stream && !uc->c->body_done) {
                conn_pump_body(uc->c);
                pumped = 1;
                if (s->dead)
                    return;
            }
        }
        if (!pumped || buf_readable(&s->wbuf) > 0)
            break;
    }
    s->sending = 0;
}

/* Process streams that received frames. */
static void h2u_process_streams(h2u_session_t *s)
{
    for (int i = 0; i < s->nstreams; i++) {
        uconn_t *uc = s->streams[i];
        if (!uc->h2u_dirty || uc->dead)
            continue;
        uc->h2u_dirty = 0;
        conn_t *c = uc->c;
        if (!c) {
            uconn_close(uc);
            i--;
            continue;
        }
        if (uc->h2u_failed) {
            if (!uc->head_done)
                uconn_fail(uc, "stream reset by upstream", 502, !uc->got_bytes);
            else if (c->resp_mode == RM_CLOSE)
                conn_response_done(c);
            else
                uconn_fail(uc, "response truncated", 502, 0);
            i = -1; /* list changed; restart */
            continue;
        }
        if (c->upstream_paused)
            continue;
        if (buf_readable(&uc->rbuf) == 0)
            continue;
        int before = s->nstreams;
        uconn_on_response_data(uc);
        if (s->nstreams != before)
            i = -1; /* streams finished or failed: restart the scan */
    }
}

static void h2u_session_activate(h2u_session_t *s)
{
    nghttp2_session_callbacks *cb;
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cb, h2u_on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cb, h2u_on_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, h2u_on_frame_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, h2u_on_data_chunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, h2u_on_stream_close);
    nghttp2_option *opt;
    nghttp2_option_new(&opt);
    nghttp2_option_set_no_auto_window_update(opt, 1);
    int rc = nghttp2_session_client_new2(&s->ng, cb, s, opt);
    nghttp2_option_del(opt);
    nghttp2_session_callbacks_del(cb);
    if (rc != 0) {
        h2u_session_fail(s, "cannot create HTTP/2 session");
        return;
    }
    nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, H2U_WINDOW },
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, H2U_MAX_STREAMS },
        { NGHTTP2_SETTINGS_ENABLE_PUSH, 0 },
    };
    nghttp2_submit_settings(s->ng, NGHTTP2_FLAG_NONE, iv, 3);
    nghttp2_session_set_local_window_size(s->ng, NGHTTP2_FLAG_NONE, 0, 4 * H2U_WINDOW);
    s->state = 2;
    /* submit everything that queued up while connecting */
    for (int i = 0; i < s->nstreams; i++)
        h2u_submit(s->streams[i]);
    h2u_session_send(s);
}

static void h2u_session_cb(ev_t *e, uint32_t events)
{
    h2u_session_t *s = (h2u_session_t *)e;
    if (s->dead)
        return;
    if (s->state == 0) {
        if (!(events & (EPOLLOUT | EPOLLERR | EPOLLHUP)))
            return;
        int err = 0;
        socklen_t el = sizeof err;
        if (getsockopt(s->ev.fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0)
            err = errno;
        if (err) {
            char reason[160];
            snprintf(reason, sizeof reason, "connect: %s", strerror(err));
            upstream_report_failure(s->pool, s->up, g_now, reason);
            h2u_session_fail(s, reason);
            return;
        }
#ifdef LIMER_TLS
        if (s->up->tls) {
            s->ssl = upstream_ssl_new(s->pool, s->up, s->ev.fd);
            if (!s->ssl) {
                h2u_session_fail(s, "tls: cannot create session");
                return;
            }
            static const unsigned char alpn[] = "\x02h2";
            SSL_set_alpn_protos(s->ssl, alpn, sizeof alpn - 1);
            s->state = 1;
            ev_mod(&s->ev, EPOLLIN | EPOLLOUT);
        } else
#endif
        {
            h2u_session_activate(s);
            return;
        }
    }
#ifdef LIMER_TLS
    if (s->state == 1) {
        uint32_t want = EPOLLIN;
        int hs = ssl_handshake_step(s->ssl, &want);
        if (hs < 0) {
            char reason[200];
            snprintf(reason, sizeof reason, "tls handshake: %s", ERR_reason_error_string(ERR_peek_last_error()) ? ERR_reason_error_string(ERR_peek_last_error()) : "failed");
            upstream_report_failure(s->pool, s->up, g_now, reason);
            h2u_session_fail(s, reason);
            return;
        }
        if (hs == 0) {
            ev_mod(&s->ev, want);
            return;
        }
        const unsigned char *proto = NULL;
        unsigned int plen = 0;
        SSL_get0_alpn_selected(s->ssl, &proto, &plen);
        if (!(proto && plen == 2 && memcmp(proto, "h2", 2) == 0)) {
            h2u_session_fail(s, "upstream did not negotiate HTTP/2");
            return;
        }
        h2u_session_activate(s);
        return;
    }
#endif
    if (events & EPOLLOUT)
        h2u_session_send(s);
    if (s->dead)
        return;
    if (events & (EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
        for (int i = 0; i < 8; i++) {
            ssize_t r;
#ifdef LIMER_TLS
            r = s->ssl ? ssl_read_into(s->ssl, &s->rbuf) : fd_read(s->ev.fd, &s->rbuf);
#else
            r = fd_read(s->ev.fd, &s->rbuf);
#endif
            if (r > 0)
                continue;
            if (r == -1)
                break;
            h2u_session_fail(s, r == 0 ? "HTTP/2 upstream connection closed" : "HTTP/2 upstream read error");
            return;
        }
        if (buf_readable(&s->rbuf) > 0) {
            s->in_callback++;
            ssize_t n = nghttp2_session_mem_recv(s->ng, (const uint8_t *)buf_rptr(&s->rbuf), buf_readable(&s->rbuf));
            s->in_callback--;
            if (n < 0) {
                h2u_session_fail(s, nghttp2_strerror((int)n));
                return;
            }
            buf_consume(&s->rbuf, (size_t)n);
            h2u_process_streams(s);
            if (s->dead)
                return;
            h2u_session_send(s);
        }
    }
}

static h2u_session_t *h2u_session_new(upstream_t *u, pool_t *p, config_t *cfg)
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
    h2u_session_t *s = xcalloc(1, sizeof *s);
    s->ev.fd = fd;
    s->ev.cb = h2u_session_cb;
    s->ev.destroy = h2u_session_destroy;
    s->up = u;
    s->pool = p;
    s->cfg = cfg;
    config_ref(cfg);
    buf_init(&s->rbuf);
    buf_init(&s->wbuf);
    s->next = g_h2u_sessions;
    g_h2u_sessions = s;
    u->h2u = s;
    ev_add(&s->ev, EPOLLOUT);
    return s;
}

/* Attach a new pseudo uconn for conn c to a session of upstream u. */
static uconn_t *h2u_attach(upstream_t *u, pool_t *p, config_t *cfg)
{
    h2u_session_t *s = u->h2u;
    if (s && (s->dead || s->state == 3 || s->nstreams >= H2U_MAX_STREAMS || s->cfg != cfg))
        s = NULL;
    if (!s) {
        s = h2u_session_new(u, p, cfg);
        if (!s)
            return NULL;
    }
    uconn_t *uc = xcalloc(1, sizeof *uc);
    uc->ev.fd = -1;
    uc->ev.destroy = uconn_destroy;
    uc->up = u;
    uc->pool = p;
    uc->cfg = cfg;
    config_ref(cfg);
    uc->state = US_ACTIVE;
    uc->connected = s->state == 2;
    uc->h2u = s;
    buf_init(&uc->rbuf);
    buf_init(&uc->wbuf);
    http_resp_init(&uc->resp);
    uconn_list_add(uc);
    h2u_streams_add(s, uc);
    return uc;
}

/* Called from uconn_close() for pseudo uconns. */
static void h2u_detach(uconn_t *uc)
{
    h2u_session_t *s = uc->h2u;
    uc->h2u = NULL;
    if (!s || s->dead)
        return;
    h2u_streams_del(s, uc);
    if (uc->h2u_stream_open && s->ng) {
        nghttp2_session_set_stream_user_data(s->ng, uc->h2u_stream_id, NULL);
        nghttp2_submit_rst_stream(s->ng, NGHTTP2_FLAG_NONE, uc->h2u_stream_id, NGHTTP2_CANCEL);
        uc->h2u_stream_open = 0;
        if (!s->in_callback)
            h2u_session_send(s);
    }
}

/* The client consumed `n` bytes of this stream's response buffer: open the window. */
static void h2u_consumed(uconn_t *uc, size_t n)
{
    h2u_session_t *s = uc->h2u;
    if (!s || s->dead || !s->ng)
        return;
    if (n > uc->h2u_unconsumed)
        n = uc->h2u_unconsumed;
    if (n == 0)
        return;
    uc->h2u_unconsumed -= n;
    nghttp2_session_consume(s->ng, uc->h2u_stream_id, n);
    if (!s->in_callback)
        h2u_session_send(s);
}

/* The client drained its buffer: continue delivering buffered frames. */
static void h2u_resume(uconn_t *uc)
{
    if (!uc->c || uc->dead)
        return;
    if (buf_readable(&uc->rbuf) > 0 || uc->h2u_failed) {
        uc->h2u_dirty = 1;
        h2u_session_t *s = uc->h2u;
        if (s && !s->dead && !s->in_callback)
            h2u_process_streams(s);
    }
}

static void h2u_tick(void)
{
    h2u_session_t *s = g_h2u_sessions;
    while (s) {
        h2u_session_t *next = s->next;
        if (!s->dead && s->state == 2 && s->nstreams == 0 && g_now - s->idle_since > s->pool->keepalive_timeout)
            h2u_session_close(s);
        else if (!s->dead && s->state < 2 && s->nstreams == 0)
            h2u_session_close(s);
        s = next;
    }
}

static void h2u_retire_config(config_t *old)
{
    h2u_session_t *s = g_h2u_sessions;
    while (s) {
        h2u_session_t *next = s->next;
        if (s->cfg == old && !s->dead) {
            if (s->nstreams == 0)
                h2u_session_close(s);
            else
                s->state = s->state == 2 ? 2 : s->state; /* finishes when its streams end */
        }
        s = next;
    }
}
