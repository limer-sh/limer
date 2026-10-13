/*
 * h2.inc - HTTP/2 support (included by proxy.c, requires nghttp2 + TLS).
 *
 * A TLS connection that negotiates "h2" via ALPN becomes an HTTP/2 session.
 * Each stream is represented by a virtual conn_t (no socket of its own):
 * request headers and DATA frames are assembled into an HTTP/1.1 request in
 * the stream's rbuf and handed to conn_process(), so routing, upstreams,
 * static files and compression work unchanged. The HTTP/1.1 response the
 * handlers write into the stream's wbuf is parsed back and re-framed into
 * HEADERS/DATA frames by a data provider that reads from that buffer.
 */
#include <nghttp2/nghttp2.h>

#define H2_MAX_STREAMS 128

typedef struct h2_session {
    nghttp2_session *ng;
    conn_t *c;                 /* the TLS socket connection */
    conn_t **streams;
    int nstreams, cap;
    int in_callback;
    int want_send;
    int closing;
} h2_session_t;

static void h2_session_send(conn_t *c);

static void h2_streams_add(h2_session_t *s, conn_t *st)
{
    if (s->nstreams == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 16;
        s->streams = xrealloc(s->streams, sizeof(conn_t *) * (size_t)s->cap);
    }
    s->streams[s->nstreams++] = st;
}

static void h2_streams_del(h2_session_t *s, conn_t *st)
{
    for (int i = 0; i < s->nstreams; i++)
        if (s->streams[i] == st) {
            s->streams[i] = s->streams[--s->nstreams];
            return;
        }
}

/* ---- data provider: response body from the stream's wbuf ---- */

static ssize_t h2_data_read(nghttp2_session *ng, int32_t stream_id, uint8_t *buf, size_t length,
                            uint32_t *flags, nghttp2_data_source *source, void *user_data)
{
    (void)ng; (void)stream_id; (void)user_data;
    conn_t *st = source->ptr;
    size_t n = 0;
    int eof = 0;
    if (st->h2_chunked) {
        /* decode our own chunked framing into h2_body first */
        if (buf_readable(&st->wbuf) > 0 && !st->h2_cs.done) {
            size_t consumed = 0;
            if (http_chunk_scan(&st->h2_cs, buf_rptr(&st->wbuf), buf_readable(&st->wbuf), &consumed, &st->h2_body) < 0)
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            buf_consume(&st->wbuf, consumed);
        }
        n = buf_readable(&st->h2_body);
        if (n > length)
            n = length;
        if (n)
            memcpy(buf, buf_rptr(&st->h2_body), n);
        buf_consume(&st->h2_body, n);
        eof = st->h2_cs.done && buf_readable(&st->h2_body) == 0;
    } else {
        n = buf_readable(&st->wbuf);
        if (n > length)
            n = length;
        if (n)
            memcpy(buf, buf_rptr(&st->wbuf), n);
        buf_consume(&st->wbuf, n);
        eof = st->h2_eof && buf_readable(&st->wbuf) == 0;
    }
    if (eof)
        *flags |= NGHTTP2_DATA_FLAG_EOF;
    if (n == 0 && !eof) {
        st->h2_deferred = 1;
        return NGHTTP2_ERR_DEFERRED;
    }
    return (ssize_t)n;
}

static void h2_lower(char *s)
{
    for (; *s; s++)
        *s = (char)tolower((unsigned char)*s);
}

/* The handlers wrote an HTTP/1.1 response head into wbuf: turn it into frames. */
static void h2_stream_flush(conn_t *st)
{
    conn_t *parent = st->h2_parent;
    h2_session_t *s = parent->h2;
    if (!s || s->closing || st->dead)
        return;
    if (!st->h2_submitted) {
        http_resp_t resp;
        http_resp_init(&resp);
        size_t consumed = 0;
        int rc = http_parse_response_head(&resp, buf_rptr(&st->wbuf), buf_readable(&st->wbuf), &consumed);
        if (rc == 0)
            return; /* head not complete yet */
        if (rc < 0) {
            http_resp_free(&resp);
            nghttp2_submit_rst_stream(s->ng, NGHTTP2_FLAG_NONE, st->h2_stream_id, NGHTTP2_INTERNAL_ERROR);
            s->want_send = 1;
            return;
        }
        buf_consume(&st->wbuf, consumed);
        st->h2_chunked = resp.chunked;
        memset(&st->h2_cs, 0, sizeof st->h2_cs);
        nghttp2_nv *nva = xcalloc((size_t)resp.nhdr + 1, sizeof(nghttp2_nv));
        char status[8];
        snprintf(status, sizeof status, "%d", resp.status);
        int nv = 0;
        nva[nv].name = (uint8_t *)":status";
        nva[nv].namelen = 7;
        nva[nv].value = (uint8_t *)status;
        nva[nv].valuelen = strlen(status);
        nv++;
        for (int i = 0; i < resp.nhdr; i++) {
            const char *n = resp.hdrs[i].name;
            if (http_hdr_is_hop_by_hop(n) || strcasecmp(n, "Keep-Alive") == 0)
                continue;
            h2_lower(resp.hdrs[i].name);
            nva[nv].name = (uint8_t *)resp.hdrs[i].name;
            nva[nv].namelen = strlen(n);
            nva[nv].value = (uint8_t *)resp.hdrs[i].value;
            nva[nv].valuelen = strlen(resp.hdrs[i].value);
            nva[nv].flags = NGHTTP2_NV_FLAG_NONE;
            nv++;
        }
        int bodiless = resp.status / 100 == 1 || resp.status == 204 || resp.status == 304 ||
                       (st->req.method && strcmp(st->req.method, "HEAD") == 0);
        nghttp2_data_provider prd;
        prd.source.ptr = st;
        prd.read_callback = h2_data_read;
        int r = nghttp2_submit_response(s->ng, st->h2_stream_id, nva, (size_t)nv, bodiless ? NULL : &prd);
        free(nva);
        http_resp_free(&resp);
        if (r != 0) {
            LOGW("http/2: submit_response failed: %s", nghttp2_strerror(r));
            conn_close(st);
            return;
        }
        st->h2_submitted = 1;
        st->resp_committed = 1;
        if (bodiless)
            st->h2_eof = 1;
    } else if (st->h2_deferred) {
        st->h2_deferred = 0;
        nghttp2_session_resume_data(s->ng, st->h2_stream_id);
    }
    s->want_send = 1;
    if (!s->in_callback)
        h2_session_send(parent);
}

/* ---- request assembly ---- */

static int h2_on_begin_headers(nghttp2_session *ng, const nghttp2_frame *frame, void *user_data)
{
    (void)ng;
    h2_session_t *s = user_data;
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    conn_t *parent = s->c;
    conn_t *st = xcalloc(1, sizeof *st);
    st->ev.fd = -1;
    st->ev.destroy = conn_destroy;
    st->h2_parent = parent;
    st->h2_stream_id = frame->hd.stream_id;
    st->srv = parent->srv;
    st->cfg = parent->cfg;
    config_ref(st->cfg);
    snprintf(st->listen_addr, sizeof st->listen_addr, "%s", parent->listen_addr);
    memcpy(&st->peer, &parent->peer, sizeof st->peer);
    st->peerlen = parent->peerlen;
    snprintf(st->peer_ip, sizeof st->peer_ip, "%s", parent->peer_ip);
    snprintf(st->peer_str, sizeof st->peer_str, "%s", parent->peer_str);
    buf_init(&st->rbuf);
    buf_init(&st->wbuf);
    buf_init(&st->enc_out);
    buf_init(&st->dechunk);
    buf_init(&st->h2_body);
    buf_init(&st->h2_hdrs);
    buf_init(&st->h2_reqbody);
    st->file_fd = -1;
    http_req_init(&st->req);
    st->state = CS_HEAD;
    st->deadline = g_now + st->srv->read_timeout;
    st->req_start = g_now;
    st->got_request_bytes = 1;
    conn_list_add(st);
    h2_streams_add(s, st);
    nghttp2_session_set_stream_user_data(ng, frame->hd.stream_id, st);
    return 0;
}

static int h2_on_header(nghttp2_session *ng, const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
                        const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    (void)flags; (void)user_data;
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    conn_t *st = nghttp2_session_get_stream_user_data(ng, frame->hd.stream_id);
    if (!st)
        return 0;
    if (namelen && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":method", 7) == 0)
            snprintf(st->h2_method, sizeof st->h2_method, "%.*s", (int)valuelen, value);
        else if (namelen == 5 && memcmp(name, ":path", 5) == 0)
            snprintf(st->h2_path, sizeof st->h2_path, "%.*s", (int)valuelen, value);
        else if (namelen == 10 && memcmp(name, ":authority", 10) == 0)
            snprintf(st->h2_authority, sizeof st->h2_authority, "%.*s", (int)valuelen, value);
        return 0;
    }
    /* headers that have no meaning in HTTP/2 or that we regenerate */
    if ((namelen == 14 && memcmp(name, "content-length", 14) == 0) ||
        (namelen == 17 && memcmp(name, "transfer-encoding", 17) == 0) ||
        (namelen == 10 && memcmp(name, "connection", 10) == 0) ||
        (namelen == 7 && memcmp(name, "upgrade", 7) == 0) ||
        (namelen == 10 && memcmp(name, "keep-alive", 10) == 0) ||
        (namelen == 6 && memcmp(name, "expect", 6) == 0) ||
        (namelen == 4 && memcmp(name, "host", 4) == 0))
        return 0;
    if (namelen == 6 && memcmp(name, "cookie", 6) == 0) {
        /* multiple cookie fields are joined with "; " (RFC 9113 8.2.3) */
        if (buf_readable(&st->h2_cookie) > 0)
            buf_puts(&st->h2_cookie, "; ");
        buf_append(&st->h2_cookie, value, valuelen);
        return 0;
    }
    if (buf_readable(&st->h2_hdrs) > HTTP_MAX_HEAD)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    buf_append(&st->h2_hdrs, name, namelen);
    buf_puts(&st->h2_hdrs, ": ");
    buf_append(&st->h2_hdrs, value, valuelen);
    buf_puts(&st->h2_hdrs, "\r\n");
    return 0;
}

static int h2_on_data_chunk(nghttp2_session *ng, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    (void)flags; (void)user_data;
    conn_t *st = nghttp2_session_get_stream_user_data(ng, stream_id);
    if (!st)
        return 0;
    st->h2_reqlen += len;
    if (st->h2_reqlen <= st->srv->max_body)
        buf_append(&st->h2_reqbody, data, len);
    return 0;
}

static void h2_dispatch_stream(conn_t *st)
{
    /* synthesize an HTTP/1.1 request for the normal pipeline */
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
    if (st->h2_reqlen > 0 || strcmp(st->h2_method, "POST") == 0 || strcmp(st->h2_method, "PUT") == 0 || strcmp(st->h2_method, "PATCH") == 0)
        buf_printf(&st->rbuf, "Content-Length: %zu\r\n", st->h2_reqlen);
    buf_puts(&st->rbuf, "\r\n");
    buf_append(&st->rbuf, buf_rptr(&st->h2_reqbody), buf_readable(&st->h2_reqbody));
    buf_reset(&st->h2_reqbody);
    buf_reset(&st->h2_hdrs);
    buf_reset(&st->h2_cookie);
    st->rd_eof = 1; /* nothing more will arrive for this stream */
    conn_process(st);
}

static int h2_on_frame_recv(nghttp2_session *ng, const nghttp2_frame *frame, void *user_data)
{
    (void)user_data;
    if ((frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) || frame->hd.type == NGHTTP2_DATA) {
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            conn_t *st = nghttp2_session_get_stream_user_data(ng, frame->hd.stream_id);
            if (st && !st->dead)
                h2_dispatch_stream(st);
        }
    }
    return 0;
}

static int h2_on_stream_close(nghttp2_session *ng, int32_t stream_id, uint32_t error_code, void *user_data)
{
    h2_session_t *s = user_data;
    conn_t *st = nghttp2_session_get_stream_user_data(ng, stream_id);
    if (!st)
        return 0;
    nghttp2_session_set_stream_user_data(ng, stream_id, NULL);
    if (!st->dead) {
        if (!st->h2_eof && error_code != NGHTTP2_NO_ERROR)
            LOGD("http/2: stream %d closed by peer (%s)", stream_id, nghttp2_http2_strerror(error_code));
        st->h2_detached = 1; /* the session no longer knows this stream */
        conn_close(st);
    }
    (void)s;
    return 0;
}

/* ---- session ---- */

static int h2_session_start(conn_t *c)
{
    nghttp2_session_callbacks *cb;
    if (nghttp2_session_callbacks_new(&cb) != 0)
        return -1;
    nghttp2_session_callbacks_set_on_begin_headers_callback(cb, h2_on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cb, h2_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, h2_on_data_chunk);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, h2_on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, h2_on_stream_close);
    h2_session_t *s = xcalloc(1, sizeof *s);
    s->c = c;
    int rc = nghttp2_session_server_new(&s->ng, cb, s);
    nghttp2_session_callbacks_del(cb);
    if (rc != 0) {
        free(s);
        return -1;
    }
    nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, H2_MAX_STREAMS },
        { NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, HTTP_MAX_HEAD },
    };
    nghttp2_submit_settings(s->ng, NGHTTP2_FLAG_NONE, iv, 2);
    c->h2 = s;
    c->state = CS_H2;
    c->deadline = g_now + c->srv->idle_timeout;
    h2_session_send(c);
    return 0;
}

static void h2_session_send(conn_t *c)
{
    h2_session_t *s = c->h2;
    if (!s || c->dead)
        return;
    s->want_send = 0;
    for (;;) {
        const uint8_t *data;
        ssize_t n = nghttp2_session_mem_send(s->ng, &data);
        if (n <= 0)
            break;
        buf_append(&c->wbuf, data, (size_t)n);
        if (buf_readable(&c->wbuf) > H2_SEND_HIGH)
            break;
    }
    conn_flush(c);
    if (c->dead)
        return;
    /* streams whose body buffers drained can take more data */
    for (int i = 0; i < s->nstreams; i++) {
        conn_t *st = s->streams[i];
        if (st->dead)
            continue;
        if (st->upstream_paused && st->uc && buf_readable(&st->wbuf) < WBUF_LOW_WATER) {
            st->upstream_paused = 0;
            ev_mod(&st->uc->ev, EPOLLIN | EPOLLRDHUP | (buf_readable(&st->uc->wbuf) ? EPOLLOUT : 0));
        }
        if (st->file_fd >= 0 && buf_readable(&st->wbuf) < WBUF_LOW_WATER)
            file_pump(st);
    }
    if (!nghttp2_session_want_read(s->ng) && !nghttp2_session_want_write(s->ng) && buf_readable(&c->wbuf) == 0) {
        conn_close(c);
        return;
    }
    conn_update_mask(c);
}

static void h2_session_recv(conn_t *c)
{
    h2_session_t *s = c->h2;
    if (!s || buf_readable(&c->rbuf) == 0)
        return;
    s->in_callback++;
    ssize_t n = nghttp2_session_mem_recv(s->ng, (const uint8_t *)buf_rptr(&c->rbuf), buf_readable(&c->rbuf));
    s->in_callback--;
    if (n < 0) {
        LOGD("http/2: %s", nghttp2_strerror((int)n));
        conn_close(c);
        return;
    }
    buf_consume(&c->rbuf, (size_t)n);
    c->deadline = g_now + c->srv->idle_timeout;
    h2_session_send(c);
}

/* Called from conn_close() for a session connection: tear down its streams. */
static void h2_session_close(conn_t *c)
{
    h2_session_t *s = c->h2;
    if (!s)
        return;
    s->closing = 1;
    while (s->nstreams > 0) {
        conn_t *st = s->streams[s->nstreams - 1];
        st->h2_detached = 1;
        h2_streams_del(s, st);
        conn_close(st);
    }
    nghttp2_session_del(s->ng);
    free(s->streams);
    free(s);
    c->h2 = NULL;
}

/* Called from conn_close() for a stream. */
static void h2_stream_close(conn_t *st)
{
    conn_t *parent = st->h2_parent;
    h2_session_t *s = parent ? parent->h2 : NULL;
    if (!s)
        return;
    h2_streams_del(s, st);
    if (!s->closing && !st->h2_detached) {
        nghttp2_session_set_stream_user_data(s->ng, st->h2_stream_id, NULL);
        if (!st->h2_eof || !st->h2_submitted)
            nghttp2_submit_rst_stream(s->ng, NGHTTP2_FLAG_NONE, st->h2_stream_id, NGHTTP2_INTERNAL_ERROR);
        s->want_send = 1;
        if (!s->in_callback)
            h2_session_send(parent);
    }
    if (g_shutting_down && s->nstreams == 0 && !s->closing && !parent->dead) {
        nghttp2_session_terminate_session(s->ng, NGHTTP2_NO_ERROR);
        s->want_send = 1;
        if (!s->in_callback)
            h2_session_send(parent);
    }
}
