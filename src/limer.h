/*
 * limer.h - shared declarations for Limer, an HTTP load balancer with
 * payload-based request distribution.
 */
#ifndef LIMER_H
#define LIMER_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <regex.h>

#ifdef LIMER_TLS
#include <openssl/ssl.h>
#endif

#define LIMER_VERSION "0.1.0"

typedef struct buf buf_t;

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */

enum { LOG_DEBUG = 0, LOG_INFO, LOG_WARN, LOG_ERROR };

extern int log_level;
void log_set_level_name(const char *name);
void log_msg(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void log_access(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_access_to(int fd, const char *line, size_t len);
/* open an access log destination: "stdout", "stderr" or a file path; returns fd or -1 */
int  log_open_target(const char *spec, char *err, size_t errlen);
void log_json_escape(buf_t *b, const char *s);

#define LOGD(...) do { if (log_level <= LOG_DEBUG) log_msg(LOG_DEBUG, __VA_ARGS__); } while (0)
#define LOGI(...) do { if (log_level <= LOG_INFO)  log_msg(LOG_INFO,  __VA_ARGS__); } while (0)
#define LOGW(...) do { if (log_level <= LOG_WARN)  log_msg(LOG_WARN,  __VA_ARGS__); } while (0)
#define LOGE(...) log_msg(LOG_ERROR, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* Utilities                                                           */
/* ------------------------------------------------------------------ */

double now_mono(void);                 /* monotonic seconds */
double now_wall(void);                 /* wall clock seconds */
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t m);
void *xrealloc(void *p, size_t n);
int parse_duration(const char *s, double *out);   /* "30s", "2m", "500ms", "1h" */
int parse_size(const char *s, size_t *out);        /* "8m", "512k", "1g", "100" */
int strcaseeq(const char *a, const char *b);
int str_has_prefix(const char *s, const char *p);
uint64_t hash64(const void *data, size_t len);
uint64_t hash64_seed(const void *data, size_t len, uint64_t seed);
int set_nonblock(int fd);
int set_cloexec(int fd);
int parse_hostport(const char *s, char **host, int *port, int default_port);
int cidr_match(const char *cidr, const struct sockaddr *addr);
void sockaddr_to_str(const struct sockaddr *sa, char *out, size_t outlen, int with_port);
int url_decode(const char *in, size_t inlen, char *out, size_t outlen);
int is_numeric(const char *s, double *out);
int glob_match(const char *pattern, const char *s);   /* '*' matches any run of chars */
int is_ip_literal(const char *s);
size_t base64_encode(const unsigned char *in, size_t n, char *out, int url);  /* out needs 4*(n/3+1)+1 */
int    base64_decode(const char *in, size_t n, unsigned char *out, size_t outcap);  /* -1 on error */
char  *path_clean(const char *path);   /* collapse //, ., ..; result starts with '/'; NULL if escaping */

/* ------------------------------------------------------------------ */
/* Growable buffer                                                     */
/* ------------------------------------------------------------------ */

struct buf {
    char *data;
    size_t off;   /* bytes already consumed from the front */
    size_t len;   /* bytes written so far                   */
    size_t cap;
};

void   buf_init(buf_t *b);
void   buf_free(buf_t *b);
void   buf_reset(buf_t *b);
int    buf_reserve(buf_t *b, size_t extra);
int    buf_append(buf_t *b, const void *p, size_t n);
int    buf_puts(buf_t *b, const char *s);
int    buf_printf(buf_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void   buf_consume(buf_t *b, size_t n);
void   buf_compact(buf_t *b);
static inline char  *buf_rptr(const buf_t *b)     { return b->data + b->off; }
static inline size_t buf_readable(const buf_t *b) { return b->len - b->off; }
static inline char  *buf_wptr(const buf_t *b)     { return b->data + b->len; }
static inline size_t buf_wavail(const buf_t *b)   { return b->cap - b->len; }
static inline void   buf_commit(buf_t *b, size_t n){ b->len += n; }

/* ------------------------------------------------------------------ */
/* HTTP/1.x parsing                                                    */
/* ------------------------------------------------------------------ */

#define HTTP_MAX_HEADERS 128
#define HTTP_MAX_HEAD    (64 * 1024)

typedef struct hdr {
    char *name;
    char *value;
} hdr_t;

typedef struct chunk_state {
    int   st;           /* internal state */
    int   ndigits;      /* hex digits seen in the current size line */
    size_t remaining;   /* bytes left in current chunk */
    int   done;
} chunk_state_t;

typedef struct http_req {
    char   *raw;        /* owned copy of the request head */
    size_t  raw_len;
    char   *method;
    char   *uri;        /* request-target as sent (or rewritten) */
    char   *uri_owned;  /* storage for a rewritten uri */
    char   *orig_path;  /* path before rewrites (NULL when unchanged) */
    char   *path;       /* owned, path part without query */
    char   *query;      /* owned, may be "" */
    int     minor;      /* HTTP/1.minor */
    hdr_t   hdrs[HTTP_MAX_HEADERS];
    int     nhdr;
    int64_t content_length; /* -1 if absent */
    int     chunked;
    int     keep_alive;
    int     expect_100;
    int     upgrade;    /* Connection: upgrade present */
    buf_t   body;       /* decoded body */
    chunk_state_t cs;
} http_req_t;

typedef struct http_resp {
    char   *raw;
    size_t  raw_len;
    int     status;
    int     minor;
    char   *reason;
    hdr_t   hdrs[HTTP_MAX_HEADERS];
    int     nhdr;
    int64_t content_length;
    int     chunked;
    int     keep_alive;
    chunk_state_t cs;
} http_resp_t;

void http_req_init(http_req_t *r);
void http_req_free(http_req_t *r);
void http_resp_init(http_resp_t *r);
void http_resp_free(http_resp_t *r);
/* return 1 = parsed (consumed set), 0 = need more data, -1 = malformed, -2 = too large */
int  http_parse_request_head(http_req_t *r, const char *data, size_t len, size_t *consumed);
int  http_parse_response_head(http_resp_t *r, const char *data, size_t len, size_t *consumed);
const char *http_hdr_get(const hdr_t *h, int n, const char *name);
int  http_hdr_is_hop_by_hop(const char *name);
int  http_hdr_connection_has(const char *conn_value, const char *token);
const char *http_status_reason(int status);
/*
 * Chunked transfer decoder/scanner. Consumes up to `len` bytes from `in`,
 * sets *consumed. If `out` is non-NULL, decoded payload is appended to it.
 * Returns 0 ok, -1 malformed. cs->done set when the terminating chunk and
 * trailers have been consumed.
 */
int  http_chunk_scan(chunk_state_t *cs, const char *in, size_t len, size_t *consumed, buf_t *out);

/* ------------------------------------------------------------------ */
/* JSON path extraction                                                */
/* ------------------------------------------------------------------ */

enum { JSON_NONE = 0, JSON_STRING, JSON_NUMBER, JSON_BOOL, JSON_NULL, JSON_OBJECT, JSON_ARRAY };

/*
 * Locate `path` (dot notation, e.g. "user.id", "items[0].sku") inside a JSON
 * document. On success returns the value type and fills `out` with a textual
 * representation: strings are unescaped, numbers/bools/null are returned as
 * literal text, objects/arrays as their raw JSON. Returns JSON_NONE when not
 * found or the document is malformed.
 */
int json_extract(const char *doc, size_t len, const char *path, buf_t *out);

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

enum lb_policy {
    LB_ROUND_ROBIN = 0,
    LB_LEAST_CONN,
    LB_RANDOM,
    LB_FIRST,
    LB_HASH,            /* rendezvous hash on a key source */
};

enum key_src {
    KS_NONE = 0,
    KS_CLIENT_IP,
    KS_HEADER,
    KS_COOKIE,
    KS_QUERY,
    KS_PATH,
    KS_URI,
    KS_JSON,
    KS_FORM,
    KS_BODY,
    KS_METHOD,
    KS_HOST,
};

typedef struct keysrc {
    int   src;      /* enum key_src */
    char *name;     /* header/cookie/query/form name or json path */
} keysrc_t;

enum match_op {
    OP_EQ = 0, OP_NE, OP_RE, OP_NRE, OP_GT, OP_LT, OP_GE, OP_LE,
    OP_EXISTS, OP_MISSING, OP_PREFIX, OP_CONTAINS,
};

typedef struct matcher {
    keysrc_t key;
    int      op;
    char   **vals;
    int      nvals;
    regex_t *re;        /* compiled for OP_RE / OP_NRE, one per value */
    double  *nums;      /* parsed for numeric ops */
    int      negate;
} matcher_t;

typedef struct hdr_op {
    int   kind;         /* 0 set, 1 add, 2 delete */
    char *name;
    char *value;
} hdr_op_t;

struct uconn;
struct hc_conn;

typedef struct upstream {
    char *hostport;
    char *host;
    int   port;
    int   weight;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int   resolved;

    /* runtime state */
    int   active;             /* in-flight requests */
    uint64_t requests;
    uint64_t failures;
    uint64_t responses;
    int   fails;              /* consecutive passive failures */
    double fail_until;        /* passive: considered down until this time */
    int   hc_status;          /* active: 0 unknown, 1 up, -1 down */
    double hc_last;
    double hc_next;
    char  hc_detail[96];
    int   cur_weight;         /* smooth weighted round robin */
    struct uconn *idle;       /* idle keep-alive connections */
    int   nidle;
    struct hc_conn *hc;       /* in-flight health check */
} upstream_t;

typedef struct pool {
    char *name;
    upstream_t **ups;
    int   nups;
    int   total_weight;
    int   policy;
    keysrc_t key;
    int   retries;
    int   max_fails;
    double fail_timeout;
    int   unhealthy_5xx;      /* count 5xx as passive failures */
    char *health_uri;
    char *health_host;
    double health_interval;
    double health_timeout;
    int   health_status;      /* expected status, 0 = any 2xx/3xx */
    double connect_timeout;
    double response_timeout;
    int   keepalive_idle;
    double keepalive_timeout;
    int   rr_index;
    hdr_op_t *hdr_up;   int n_hdr_up;
    hdr_op_t *hdr_down; int n_hdr_down;
    int   preserve_host;      /* pass Host header through (default on) */
} pool_t;

enum route_kind { ROUTE_PROXY = 0, ROUTE_RESPOND, ROUTE_REDIRECT, ROUTE_ERROR, ROUTE_ABORT, ROUTE_FILES };

enum rewrite_kind { RW_PATH = 0, RW_STRIP_PREFIX, RW_STRIP_SUFFIX, RW_REPLACE, RW_URI };

typedef struct rewrite {
    int   kind;
    char *a;        /* path / prefix / suffix / search */
    char *b;        /* replacement */
} rewrite_t;

typedef struct auth_user {
    char *name;
    char *hash;     /* bcrypt ($2a$/$2b$/$2y$) or any crypt(3) hash */
} auth_user_t;

typedef struct basic_auth {
    auth_user_t *users;
    int   nusers;
    char *realm;
} basic_auth_t;

typedef struct file_server {
    char *root;
    char **index;  int nindex;
    int   browse;
    char **try_files; int ntry;
    int   hide_dotfiles;
} file_server_t;

typedef struct route {
    char     *name;
    matcher_t *m;
    int       nm;
    int       kind;
    pool_t   *pool;
    int       resp_status;
    char     *resp_body;
    hdr_op_t *hdr_down; int n_hdr_down;
    rewrite_t *rw; int nrw;
    basic_auth_t *auth;
    file_server_t *files;
} route_t;

enum tls_mode { TLS_NONE = 0, TLS_FILES, TLS_INTERNAL, TLS_AUTO };

typedef struct server {
    char  **addrs;       /* bind addresses ("host:port" / ":port"), one listener each */
    int     naddr;
    char  **hosts;       /* hostnames this site answers for (glob allowed); none = catch-all */
    int     nhosts;
    int     port;        /* port of the first address, for redirects/logging */
    route_t **routes;
    int     nroutes;
    size_t  max_body;
    double  read_timeout;
    double  idle_timeout;
    int     access_log;
    int     log_fd;      /* -1 none; 1 stdout; 2 stderr; else an opened file */
    int     log_json;
    int     is_admin;
    int     tls_mode;    /* enum tls_mode */
    char   *tls_cert;
    char   *tls_key;
    hdr_op_t *hdr_down; int n_hdr_down;   /* `header` directive: all responses */
    hdr_op_t *hdr_up;   int n_hdr_up;     /* `request_header`: all proxied requests */
    basic_auth_t *auth;                   /* server-wide basic_auth */
    char   *encode;      /* "gzip zstd br" or NULL */
    int     encode_min;
    int     redirect_https;   /* http listener that redirects to https (auto https) */
#ifdef LIMER_TLS
    SSL_CTX *ssl_ctx;
#endif
} server_t;

typedef struct config {
    char    *path;
    char    *text;
    server_t **servers;
    int      nservers;
    int      workers;
    int      max_connections;   /* per worker, 0 = unlimited */
    char    *admin_addr;
    char    *pidfile;
    int      log_level;
    double   grace;
    int      http_port;         /* default 80  */
    int      https_port;        /* default 443 */
    char    *storage;           /* certificate / state directory */
    char    *acme_ca;           /* ACME directory URL */
    char    *acme_ca_root;      /* PEM bundle to trust for the ACME CA (testing) */
    char    *acme_email;
    int      acme_disabled;     /* auto_https off */
    int      refs;
} config_t;

config_t *config_load(const char *path, char *err, size_t errlen);
config_t *config_parse(const char *text, const char *path, char *err, size_t errlen);
void      config_ref(config_t *c);
void      config_unref(config_t *c);
const char *lb_policy_name(int p);
const char *keysrc_name(int s);

/* ------------------------------------------------------------------ */
/* Request matching and key extraction                                 */
/* ------------------------------------------------------------------ */

typedef struct req_ctx {
    http_req_t *req;
    const struct sockaddr *peer;
    socklen_t peerlen;
    char peer_ip[64];
    int tls;
} req_ctx_t;

/* Extract a key from the request. Returns 1 and fills `out` when present. */
int  key_extract(const keysrc_t *k, const req_ctx_t *ctx, buf_t *out);
int  matcher_eval(const matcher_t *m, const req_ctx_t *ctx);
int  route_matches(const route_t *r, const req_ctx_t *ctx);

/* ------------------------------------------------------------------ */
/* Balancing                                                           */
/* ------------------------------------------------------------------ */

int  upstream_healthy(const upstream_t *u, double now);
/* Select an upstream. `tried` is a bitmask of indexes to skip. Returns NULL if none. */
upstream_t *pool_select(pool_t *p, const req_ctx_t *ctx, uint64_t tried, double now, int *idx_out, char *why, size_t whylen);
void upstream_report_failure(pool_t *p, upstream_t *u, double now, const char *reason);
void upstream_report_success(pool_t *p, upstream_t *u);

/* ------------------------------------------------------------------ */
/* Proxy / event loop                                                  */
/* ------------------------------------------------------------------ */

int  proxy_run(config_t *cfg, int worker_id);  /* blocks until shutdown */
void proxy_request_reload(void);
void proxy_request_shutdown(void);

/* ------------------------------------------------------------------ */
/* TLS                                                                 */
/* ------------------------------------------------------------------ */

/* Compression (encode.c) */
typedef struct encoder encoder_t;
encoder_t  *encoder_new(const char *name);                 /* "gzip", "zstd" or "br" */
int         encoder_write(encoder_t *e, const void *in, size_t n, buf_t *out, int flush); /* 0 none, 1 sync, 2 finish */
void        encoder_free(encoder_t *e);
const char *encode_name(const encoder_t *e);
const char *encode_choose(const char *server_list, const char *accept_encoding);
int         encode_compressible(const char *content_type);
int         encode_available(void);

/* Static files (files.c) */
const char *mime_type_for(const char *path);
void        http_date(time_t t, char *out, size_t n);
time_t      http_date_parse(const char *s);
int         files_listing(const char *dir, const char *urlpath, int hide_dotfiles, buf_t *out);
int         path_has_dotfile(const char *clean);

/* ACME (acme.c) */
int  acme_load_stored(config_t *cfg, server_t *s, char *err, size_t errlen);
int  acme_manager_start(config_t *cfg);   /* fork the certificate manager if needed */
void acme_manager_stop(void);
int  acme_challenge_lookup(const config_t *cfg, const char *token, buf_t *out);

int  tls_init_server(server_t *s, char *err, size_t errlen);   /* from files */
int  tls_init_internal(server_t *s, char *err, size_t errlen); /* self-signed for its hosts */
int  tls_load_pem(server_t *s, const char *cert, const char *key, char *err, size_t errlen);
void tls_free_server(server_t *s);
#ifdef LIMER_TLS
void tls_set_sni_resolver(SSL_CTX *(*fn)(SSL *, const char *));
#endif
/* basic auth */
int  auth_verify(const basic_auth_t *a, const char *authorization_header);

#endif /* LIMER_H */
