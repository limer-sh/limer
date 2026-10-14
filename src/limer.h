/*
 * limer.h - shared declarations for limer.sh, an HTTP load balancer with
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
#include "compat.h"

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
int    mkdir_p(const char *path);

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
    buf_t *trailers;    /* optional: raw trailer lines ("name: value\r\n"...) are appended here */
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
    LB_STICKY,          /* cookie-based sticky sessions */
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
    KS_TLS_CLIENT,      /* client certificate: subject, issuer, serial, fingerprint, verified */
};

/* What the TLS client presented (filled after the handshake). */
typedef struct tls_client_info {
    int  present;             /* a certificate was presented */
    int  verified;            /* ... and it chains to a trusted CA */
    char subject[512];
    char issuer[512];
    char serial[96];
    char fingerprint[72];     /* sha256, lowercase hex */
} tls_client_info_t;

enum client_auth_mode { CA_NONE = 0, CA_REQUEST, CA_REQUIRE, CA_VERIFY_IF_GIVEN, CA_REQUIRE_AND_VERIFY };

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
    int      is_split;  /* traffic split: match a deterministic fraction of requests */
    double   split_pct; /* 0..100 */
    keysrc_t split_key; /* key the split hashes (default client_ip) */
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
    int   tls;                /* connect with TLS (https:// upstream) */
    int   h2;                 /* speak HTTP/2 (h2c:// or transport versions h2) */
    void *h2u;                /* runtime: current HTTP/2 session */
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int   resolved;
    int   dynamic;            /* came from a DNS lookup (dynamic a / srv) */
    double resolve_next;      /* runtime: next re-resolution of a named static upstream */
    int   gone;               /* removed from the pool; freed once nothing references it */

    /* runtime state */
    int   drained;            /* runtime: take no new requests */
    char  sticky_id[20];      /* value used in sticky cookies */
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
    int  *retry_status;       /* try the next upstream when one answers with one of these */
    int   nretry_status;
    int  *redirect_status;    /* when the final answer has one of these, redirect the client instead */
    int   nredirect_status;
    char *redirect_to;        /* redirect target, placeholders allowed */
    int   redirect_code;      /* 302 unless configured */
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
    int   upstream_h2;        /* 1 = h2 over TLS, 2 = h2c, applied to all upstreams */
    int   tls_insecure;       /* skip upstream certificate verification */
    char *tls_server_name;    /* SNI / verification name for upstream TLS */
    char *tls_ca;             /* PEM bundle to trust for upstream TLS */
    char *tls_client_cert;    /* client certificate (chain) presented to upstreams */
    char *tls_client_key;
    int   tls_all;            /* `tls` in the pool block: every upstream speaks TLS */
    struct pool *mirror;      /* shadow pool: a copy of the request is sent here, response discarded */
    double mirror_sample;     /* 0..100 percent of requests to mirror (default 100) */
    /* dynamic upstreams */
    int   dyn_kind;           /* 0 static, 1 A/AAAA lookup, 2 SRV lookup */
    char *dyn_name;
    int   dyn_port;           /* for A lookups */
    double refresh;           /* re-resolution interval, 0 = never */
    double dyn_next;          /* runtime: next lookup */
    int   dyn_inflight;       /* runtime: a lookup is queued */
    upstream_t **retired;     /* runtime: removed upstreams still referenced */
    int   nretired;
#ifdef LIMER_TLS
    SSL_CTX *client_ctx;      /* for https upstreams */
#endif
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

/* rate limiting (ratelimit.c) */
typedef struct ratelimit ratelimit_t;
ratelimit_t *ratelimit_new(double rate, double burst, int max_keys);
void         ratelimit_free(ratelimit_t *rl);
int          ratelimit_check(ratelimit_t *rl, const char *key, double now, double *retry_after);
void         ratelimit_stats(const ratelimit_t *rl, uint64_t *hits, uint64_t *limited, int *keys);
double       ratelimit_rate(const ratelimit_t *rl);

typedef struct rate_limit_cfg {
    char  *name;        /* zone name for metrics */
    char  *key;         /* placeholder template, default {remote_ip} */
    double rate;        /* requests per second */
    double burst;
    int    status;      /* default 429 */
    int    max_keys;
    ratelimit_t *rl;    /* runtime table */
} rate_limit_cfg_t;

/* per-source-IP admission control (ipguard.c): L7 DoS mitigation at accept() */
typedef struct ipguard_cfg {
    int    enabled;
    int    max_conns_per_ip;   /* cap concurrent connections per IP; 0 = off */
    double conn_rate;          /* new connections/sec per IP; 0 = off */
    double conn_burst;         /* bucket size; default = conn_rate */
    int    ban_threshold;      /* strikes within the window that trigger a ban; 0 = banning off */
    double ban_window;         /* seconds the strikes are counted over (default 10s) */
    double ban_duration;       /* seconds an address stays banned; 0 = banning off */
    int    max_keys;           /* table cap (default 1,000,000) */
} ipguard_cfg_t;

/* admin API protection: admin <addr> { secret; rate; burst; max_failures; ban } */
typedef struct admin_cfg {
    char  *secret;        /* required as "Authorization: Bearer <secret>" on every endpoint but /health; NULL = open */
    double rate;          /* webhook calls (/drain, /undrain, /scale_up) per second per caller IP; 0 = unlimited */
    double burst;         /* bucket size for those calls */
    int    max_failures;  /* wrong secrets and rate-limit hits before a ban; 0 = never ban */
    double ban;           /* seconds a banned caller is refused; strikes are also counted over this window */
} admin_cfg_t;

typedef struct ipguard ipguard_t;
enum { IPGUARD_OK = 0, IPGUARD_BANNED, IPGUARD_CONN_LIMIT, IPGUARD_RATE };
ipguard_t *ipguard_new(int max_keys);
void       ipguard_free(ipguard_t *g);
/* Decide a freshly-accepted connection from `ip`. Returns IPGUARD_OK (and
 * counts a live connection) or one of the refusal reasons above. */
int        ipguard_admit(ipguard_t *g, const ipguard_cfg_t *cfg, const char *ip, double now);
void       ipguard_release(ipguard_t *g, const char *ip);   /* a tracked connection closed */
/* Layer 2 (post-header, keyed on the effective client IP): enforce and build bans. */
int        ipguard_is_banned(ipguard_t *g, const char *ip, double now);
void       ipguard_strike(ipguard_t *g, const ipguard_cfg_t *cfg, const char *ip, double now);
void       ipguard_stats(const ipguard_t *g, uint64_t *admitted, uint64_t *ref_conn,
                         uint64_t *ref_rate, uint64_t *ref_ban, uint64_t *bans, int *tracked);

/* revert a reload whose new config makes responses fail */
typedef struct rollback_cfg {
    int    enabled;
    double error_rate;    /* 5xx share during probation that triggers a revert (0..1); default 0.5 */
    double window;        /* probation after a reload (s); default 15 */
    int    min_requests;  /* responses needed before judging; default 20 */
    int    canary;        /* % of new connections that use the new config during probation; default 5, 100 = all */
} rollback_cfg_t;

/* scale-up hook: run a command when load spikes, e.g. to add backends */
typedef struct scale_cfg {
    int    enabled;
    double requests;      /* per-worker requests/sec that counts as a spike; 0 = off */
    int    connections;   /* active-connection count that counts as a spike; 0 = off */
    double sustain;       /* load must stay above the threshold this long (s); default 0 */
    double cooldown;      /* minimum seconds between hook runs; default 60 */
    char  *exec;          /* command run via `sh -c` when triggered */
} scale_cfg_t;

typedef struct cache_cfg {
    double ttl;           /* default freshness when the response has none (0 = only cache if it says so) */
    double swr;           /* stale-while-revalidate window */
    size_t max_object;    /* largest response body to store */
    int    methods_head;  /* cache HEAD as well as GET (default yes) */
} cache_cfg_t;

/* cache.c: per-worker in-memory response cache */
typedef struct cache cache_t;
typedef struct cache_entry cache_entry_t;
cache_t *cache_new(size_t capacity);
void     cache_free(cache_t *c);
cache_entry_t *cache_get(cache_t *c, const char *key);
void     cache_touch_stats(cache_t *c, int hit);
int      cache_entry_state(const cache_entry_t *e, double now);   /* 0 fresh, 1 serve-stale, 2 stale */
double   cache_entry_age(const cache_entry_t *e, double now);
int      cache_entry_status(const cache_entry_t *e);
const char *cache_entry_reason(const cache_entry_t *e);
const char *cache_entry_body(const cache_entry_t *e, size_t *len);
const char *cache_entry_etag(const cache_entry_t *e);
const char *cache_entry_last_modified(const cache_entry_t *e);
int      cache_entry_nhdr(const cache_entry_t *e);
const char *cache_entry_hdr_name(const cache_entry_t *e, int i);
const char *cache_entry_hdr_value(const cache_entry_t *e, int i);
const char *cache_entry_vary(const cache_entry_t *e);
const char *cache_entry_vary_val(const cache_entry_t *e);
void     cache_entry_set_revalidating(cache_entry_t *e, int v);
void     cache_entry_refresh(cache_t *c, cache_entry_t *e, double now, double ttl, double swr);
void     cache_store(cache_t *c, const char *key, int status, const char *reason,
                     const char *const *hdr_names, const char *const *hdr_values, int nhdr,
                     const char *body, size_t body_len, double now, double ttl, double swr,
                     const char *etag, const char *last_modified, const char *vary, const char *vary_val);
void     cache_stats(cache_t *c, uint64_t *hits, uint64_t *misses, uint64_t *stores, uint64_t *evictions,
                     int *count, size_t *bytes, size_t *capacity);
int      cache_purge(cache_t *c, const char *key);
void     cache_clear(cache_t *c);

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
    rate_limit_cfg_t *rl;
    cache_cfg_t *cache;     /* response caching for this route */
    int       needs_body;   /* a matcher, hash key or placeholder reads the request body */
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
    int     body_mode;   /* 0 stream when nothing reads the body, 1 always buffer */
    int     needs_body;  /* a site-level rate limit key or request_header reads the body */
    double  read_timeout;
    double  idle_timeout;
    int     access_log;
    int     log_fd;      /* -1 none; 1 stdout; 2 stderr; else an opened file */
    int     log_json;
    int     is_admin;
    int     tls_mode;    /* enum tls_mode */
    char   *tls_cert;
    char   *tls_key;
    int     client_auth_mode; /* enum client_auth_mode */
    char  **client_ca;        /* PEM files with CAs that may sign client certificates */
    int     nclient_ca;
    hdr_op_t *hdr_down; int n_hdr_down;   /* `header` directive: all responses */
    hdr_op_t *hdr_up;   int n_hdr_up;     /* `request_header`: all proxied requests */
    basic_auth_t *auth;                   /* server-wide basic_auth */
    rate_limit_cfg_t *rl;                 /* server-wide rate limit */
    cache_cfg_t *cache;                   /* server-wide response caching */
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
    admin_cfg_t admin;        /* secret, rate limit and bans for the admin API */
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
    int      acme_challenge;    /* 0 http-01, 1 tls-alpn-01, 2 dns-01 */
    char    *acme_dns_script;   /* "script present|cleanup <domain> <txt>" for dns-01 */
    double   acme_dns_propagation; /* wait after "present" */
    char   **resolvers;       /* DNS servers for upstream lookups (ip[:port]); empty = system */
    int      nresolvers;
    char   **trusted_proxies; /* CIDRs/IPs whose X-Forwarded-For is trusted for the client IP */
    int      ntrusted_proxies;
    size_t   cache_capacity;  /* total response cache size per worker (0 = default) */
    ipguard_cfg_t ipguard;    /* per-source-IP admission control */
    scale_cfg_t scale_up;     /* run a hook when load spikes */
    rollback_cfg_t auto_rollback; /* revert reloads that cause 5xx */
    char    *server_header;   /* value for the Server header on local responses; NULL = omit */
    int      http3;           /* also serve HTTPS sites over HTTP/3 (QUIC, UDP on the same port) */
    int      refs;
} config_t;

config_t *config_load(const char *path, char *err, size_t errlen);
extern int config_lenient_resolve;   /* reloads: an unresolvable named upstream keeps its old address */
extern int config_no_dns;            /* tests: never look names up; a named upstream stays unresolved */
/* runtime overrides (<storage>/overrides.conf): "hostport drained=<0|1> weight=<n>" per line */
int  overrides_apply(config_t *cfg);
int  overrides_apply_upstream(const config_t *cfg, upstream_t *u);
/* dynamic upstreams */
upstream_t *upstream_new_resolved(pool_t *p, const char *host, const struct sockaddr *sa, socklen_t len, int port, int weight);
void upstream_free(upstream_t *u);
void pool_recompute(pool_t *p);
int  pool_add_runtime(pool_t *p, upstream_t *u);        /* 0 ok, -1 full */
void pool_retire_upstream(pool_t *p, int idx);          /* move ups[idx] to the retired list */
void pool_reap_retired(pool_t *p);                      /* free retired upstreams nothing uses */

/* resolver.c: DNS lookups on a helper thread */
#define RESOLVE_MAX_RESULTS 64
enum { RESOLVE_ADDR = 0, RESOLVE_SRV = 1 };
typedef struct resolve_result {
    struct sockaddr_storage addr;
    socklen_t len;
    int  port;
    int  weight;
    char target[256];
} resolve_result_t;
typedef struct resolve_job {
    int  kind;
    char name[256];
    int  port;
    char resolvers[4][64];
    int  nresolvers;
    resolve_result_t res[RESOLVE_MAX_RESULTS];
    int  nres;
    char err[512];
    void *user;               /* caller context */
    void *user2;
    int  tag;                 /* caller's job classification */
    struct resolve_job *next;
} resolve_job_t;
int  resolver_start(void);                 /* returns the fd that becomes readable when results are ready */
void resolver_submit(resolve_job_t *job);
resolve_job_t *resolver_take_done(void);   /* finished jobs, oldest first; NULL when none */
void resolver_stop(void);
void resolve_sync(resolve_job_t *job);     /* blocking lookup on the calling thread */
void resolve_job_init(resolve_job_t *job, const config_t *cfg, int kind, const char *name, int port);
int  overrides_set(const config_t *cfg, const char *hostport, int drained, int weight, char *err, size_t errlen); /* -1 keeps a field */
int  overrides_clear(const config_t *cfg);
int  overrides_list(const config_t *cfg, buf_t *json);
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
    const tls_client_info_t *client_cert;   /* NULL on plain connections */
} req_ctx_t;

/* Extract a key from the request. Returns 1 and fills `out` when present. */
int  key_extract(const keysrc_t *k, const req_ctx_t *ctx, buf_t *out);
int  matcher_eval(const matcher_t *m, const req_ctx_t *ctx);
int  route_matches(const route_t *r, const req_ctx_t *ctx);
int  route_prematch(const route_t *r, const req_ctx_t *ctx);  /* 0 no match, 1 match, 2 the body decides */
int  keysrc_needs_body(const keysrc_t *k);
int  template_needs_body(const char *tmpl);   /* placeholder string reads {json.*}, {form.*} or {body} */
int  route_compute_needs_body(route_t *r);

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
/* The master, before forking: bind the listeners the workers will share, where the kernel does not
 * balance SO_REUSEPORT across processes (a no-op on Linux); drop the ones a reload removed. */
int  proxy_prebind(config_t *cfg, char *err, size_t errlen);
void proxy_prebind_prune(config_t *cfg);
void proxy_request_reload(void);
void proxy_request_shutdown(void);
/* Page shared with the master across fork. Workers write the counters, the
 * master writes the canary controls. */
enum {
    SH_REQ = 0,     /* responses (new config while a canary runs, else all) */
    SH_ERR,         /* ...of which 5xx */
    SH_OLD_REQ,     /* responses served by the previous config during a canary */
    SH_OLD_ERR,     /* ...of which 5xx */
    SH_CANARY,      /* % of new connections that get the new config; 0 = no canary */
    SH_CANARY_GEN,  /* bumped by the master at the start of each probation */
    SH_SCALE_LAST,  /* CLOCK_MONOTONIC ms of the last scale_up run, so every worker shares one cooldown */
    SH_SLOTS
};
void proxy_set_shared_stats(uint64_t *counters);

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
void tls_client_info(SSL *ssl, tls_client_info_t *out);   /* after the handshake */
int  tls_init_pool_client(pool_t *p, char *err, size_t errlen);  /* client context for https upstreams */
void tls_free_pool_client(pool_t *p);
#ifdef LIMER_TLS
void tls_set_sni_resolver(SSL_CTX *(*fn)(SSL *, const char *));
/* tls-alpn-01: resolver returns 1 and the key authorisation for a name under validation */
void tls_set_acme_resolver(int (*fn)(SSL *, const char *name, char *keyauth, size_t n));
#endif
/* basic auth */
int  auth_verify(const basic_auth_t *a, const char *authorization_header);

#endif /* LIMER_H */
