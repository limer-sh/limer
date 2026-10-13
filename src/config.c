/*
 * config.c - Limerfile parser.
 *
 * The syntax follows the Caddyfile conventions: whitespace-separated tokens,
 * one directive per line, blocks delimited by '{' at the end of a line and
 * '}' on its own line, '#' comments, and quoted strings.
 */
#include "limer.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------ */
/* Tokenizer                                                           */
/* ------------------------------------------------------------------ */

typedef struct tok {
    char *s;
    int line;
    int nl;      /* a newline precedes this token */
    int quoted;
} tok_t;

typedef struct toks {
    tok_t *v;
    int n, cap;
} toks_t;

static void toks_push(toks_t *t, char *s, int line, int nl, int quoted)
{
    if (t->n == t->cap) {
        t->cap = t->cap ? t->cap * 2 : 64;
        t->v = xrealloc(t->v, sizeof(tok_t) * (size_t)t->cap);
    }
    t->v[t->n].s = s;
    t->v[t->n].line = line;
    t->v[t->n].nl = nl;
    t->v[t->n].quoted = quoted;
    t->n++;
}

static void toks_free(toks_t *t)
{
    for (int i = 0; i < t->n; i++)
        free(t->v[i].s);
    free(t->v);
}

static int tokenize(const char *text, toks_t *t, char *err, size_t errlen)
{
    const char *p = text;
    int line = 1;
    int nl = 1;
    buf_t cur;
    buf_init(&cur);
    while (*p) {
        if (*p == '\n') {
            nl = 1;
            line++;
            p++;
            continue;
        }
        if (isspace((unsigned char)*p)) {
            p++;
            continue;
        }
        if (*p == '#') {
            while (*p && *p != '\n')
                p++;
            continue;
        }
        int tline = line;
        buf_reset(&cur);
        if (*p == '"') {
            p++;
            while (*p && *p != '"') {
                if (*p == '\\' && p[1]) {
                    p++;
                    char c = *p;
                    if (c == 'n') c = '\n';
                    else if (c == 't') c = '\t';
                    else if (c == 'r') c = '\r';
                    buf_append(&cur, &c, 1);
                } else {
                    if (*p == '\n')
                        line++;
                    buf_append(&cur, p, 1);
                }
                p++;
            }
            if (*p != '"') {
                snprintf(err, errlen, "line %d: unterminated quoted string", tline);
                buf_free(&cur);
                return -1;
            }
            p++;
            toks_push(t, xstrndup(cur.data ? cur.data : "", cur.len), tline, nl, 1);
        } else if (*p == '`') {
            p++;
            while (*p && *p != '`') {
                if (*p == '\n')
                    line++;
                buf_append(&cur, p, 1);
                p++;
            }
            if (*p != '`') {
                snprintf(err, errlen, "line %d: unterminated raw string", tline);
                buf_free(&cur);
                return -1;
            }
            p++;
            toks_push(t, xstrndup(cur.data ? cur.data : "", cur.len), tline, nl, 1);
        } else {
            while (*p && !isspace((unsigned char)*p))
                buf_append(&cur, p++, 1);
            toks_push(t, xstrndup(cur.data, cur.len), tline, nl, 0);
        }
        nl = 0;
    }
    buf_free(&cur);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Block tree                                                          */
/* ------------------------------------------------------------------ */

typedef struct node {
    char **args;
    int nargs;
    struct node **kids;
    int nkids;
    int line;
} node_t;

static void node_free(node_t *n)
{
    if (!n)
        return;
    for (int i = 0; i < n->nargs; i++)
        free(n->args[i]);
    free(n->args);
    for (int i = 0; i < n->nkids; i++)
        node_free(n->kids[i]);
    free(n->kids);
    free(n);
}

static int is_open(const tok_t *t)  { return !t->quoted && strcmp(t->s, "{") == 0; }
static int is_close(const tok_t *t) { return !t->quoted && strcmp(t->s, "}") == 0; }

static int parse_block(toks_t *t, int *i, node_t *parent, int nested, char *err, size_t errlen);

static node_t *parse_directive(toks_t *t, int *i, char *err, size_t errlen)
{
    node_t *n = xcalloc(1, sizeof *n);
    n->line = t->v[*i].line;
    int first = 1;
    while (*i < t->n && (first || !t->v[*i].nl)) {
        tok_t *tk = &t->v[*i];
        if (is_close(tk) && !first)
            break;
        if (is_open(tk)) {
            (*i)++;
            if (*i < t->n && !t->v[*i].nl && !is_close(&t->v[*i])) {
                snprintf(err, errlen, "line %d: '{' must end its line", tk->line);
                node_free(n);
                return NULL;
            }
            if (parse_block(t, i, n, 1, err, errlen) < 0) {
                node_free(n);
                return NULL;
            }
            return n;
        }
        n->args = xrealloc(n->args, sizeof(char *) * (size_t)(n->nargs + 1));
        n->args[n->nargs++] = xstrdup(tk->s);
        (*i)++;
        first = 0;
    }
    return n;
}

static int parse_block(toks_t *t, int *i, node_t *parent, int nested, char *err, size_t errlen)
{
    while (*i < t->n) {
        tok_t *tk = &t->v[*i];
        if (is_close(tk)) {
            if (!nested) {
                snprintf(err, errlen, "line %d: unexpected '}'", tk->line);
                return -1;
            }
            (*i)++;
            return 0;
        }
        node_t *d = parse_directive(t, i, err, errlen);
        if (!d)
            return -1;
        parent->kids = xrealloc(parent->kids, sizeof(node_t *) * (size_t)(parent->nkids + 1));
        parent->kids[parent->nkids++] = d;
    }
    if (nested) {
        snprintf(err, errlen, "unexpected end of file: missing '}'");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Interpretation helpers                                              */
/* ------------------------------------------------------------------ */

#define FAIL(...) do { snprintf(err, errlen, __VA_ARGS__); return -1; } while (0)

static int want_args(node_t *n, int min, int max, char *err, size_t errlen)
{
    int have = n->nargs - 1;
    if (have < min || (max >= 0 && have > max)) {
        if (min == max)
            FAIL("line %d: '%s' expects %d argument%s", n->line, n->args[0], min, min == 1 ? "" : "s");
        if (max < 0)
            FAIL("line %d: '%s' expects at least %d argument%s", n->line, n->args[0], min, min == 1 ? "" : "s");
        FAIL("line %d: '%s' expects %d to %d arguments", n->line, n->args[0], min, max);
    }
    return 0;
}

static int arg_duration(node_t *n, int idx, double *out, char *err, size_t errlen)
{
    if (parse_duration(n->args[idx], out) < 0)
        FAIL("line %d: '%s': invalid duration '%s'", n->line, n->args[0], n->args[idx]);
    return 0;
}

static int arg_int(node_t *n, int idx, int *out, int lo, int hi, char *err, size_t errlen)
{
    char *end;
    long v = strtol(n->args[idx], &end, 10);
    if (end == n->args[idx] || *end || v < lo || v > hi)
        FAIL("line %d: '%s': invalid number '%s'", n->line, n->args[0], n->args[idx]);
    *out = (int)v;
    return 0;
}

static int arg_bool(node_t *n, int idx, int *out, char *err, size_t errlen)
{
    const char *v = n->args[idx];
    if (strcaseeq(v, "on") || strcaseeq(v, "true") || strcaseeq(v, "yes") || strcmp(v, "1") == 0)
        *out = 1;
    else if (strcaseeq(v, "off") || strcaseeq(v, "false") || strcaseeq(v, "no") || strcmp(v, "0") == 0)
        *out = 0;
    else
        FAIL("line %d: '%s': expected on/off, got '%s'", n->line, n->args[0], v);
    return 0;
}

static int parse_keysrc(const char *s, int *src, int *needs_name)
{
    static const struct { const char *n; int src; int named; } tbl[] = {
        { "client_ip", KS_CLIENT_IP, 0 }, { "remote_ip", KS_CLIENT_IP, 0 }, { "ip", KS_CLIENT_IP, 0 },
        { "header", KS_HEADER, 1 }, { "cookie", KS_COOKIE, 1 }, { "query", KS_QUERY, 1 },
        { "path", KS_PATH, 0 }, { "uri", KS_URI, 0 }, { "json", KS_JSON, 1 }, { "form", KS_FORM, 1 },
        { "body", KS_BODY, 0 }, { "method", KS_METHOD, 0 }, { "host", KS_HOST, 0 },
        { NULL, 0, 0 }
    };
    for (int i = 0; tbl[i].n; i++)
        if (strcaseeq(s, tbl[i].n)) {
            *src = tbl[i].src;
            *needs_name = tbl[i].named;
            return 0;
        }
    return -1;
}

static int parse_op(const char *s, int *op)
{
    static const struct { const char *n; int op; } tbl[] = {
        { "==", OP_EQ }, { "=", OP_EQ }, { "eq", OP_EQ }, { "is", OP_EQ }, { "in", OP_EQ },
        { "!=", OP_NE }, { "ne", OP_NE }, { "not_in", OP_NE },
        { "~", OP_RE }, { "=~", OP_RE }, { "regex", OP_RE }, { "matches", OP_RE },
        { "!~", OP_NRE },
        { ">", OP_GT }, { "gt", OP_GT }, { "<", OP_LT }, { "lt", OP_LT },
        { ">=", OP_GE }, { "ge", OP_GE }, { "<=", OP_LE }, { "le", OP_LE },
        { "exists", OP_EXISTS }, { "present", OP_EXISTS },
        { "missing", OP_MISSING }, { "!exists", OP_MISSING }, { "absent", OP_MISSING },
        { "^=", OP_PREFIX }, { "prefix", OP_PREFIX }, { "starts_with", OP_PREFIX },
        { "*=", OP_CONTAINS }, { "contains", OP_CONTAINS },
        { NULL, 0 }
    };
    for (int i = 0; tbl[i].n; i++)
        if (strcmp(s, tbl[i].n) == 0) {
            *op = tbl[i].op;
            return 0;
        }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Freeing                                                             */
/* ------------------------------------------------------------------ */

static void matcher_free(matcher_t *m)
{
    free(m->key.name);
    for (int i = 0; i < m->nvals; i++) {
        free(m->vals[i]);
        if (m->re)
            regfree(&m->re[i]);
    }
    free(m->vals);
    free(m->re);
    free(m->nums);
}

static void hdr_ops_free(hdr_op_t *ops, int n)
{
    for (int i = 0; i < n; i++) {
        free(ops[i].name);
        free(ops[i].value);
    }
    free(ops);
}

static void pool_free(pool_t *p)
{
    if (!p)
        return;
    for (int i = 0; i < p->nups; i++) {
        free(p->ups[i]->hostport);
        free(p->ups[i]->host);
        free(p->ups[i]);
    }
    free(p->ups);
    free(p->name);
    free(p->key.name);
    free(p->health_uri);
    free(p->health_host);
    hdr_ops_free(p->hdr_up, p->n_hdr_up);
    hdr_ops_free(p->hdr_down, p->n_hdr_down);
    free(p);
}

static void route_free(route_t *r)
{
    if (!r)
        return;
    for (int i = 0; i < r->nm; i++)
        matcher_free(&r->m[i]);
    free(r->m);
    free(r->name);
    pool_free(r->pool);
    free(r->resp_body);
    hdr_ops_free(r->hdr_down, r->n_hdr_down);
    free(r);
}

static void server_free(server_t *s)
{
    if (!s)
        return;
    for (int i = 0; i < s->naddr; i++)
        free(s->addrs[i]);
    free(s->addrs);
    for (int i = 0; i < s->nroutes; i++)
        route_free(s->routes[i]);
    free(s->routes);
    free(s->tls_cert);
    free(s->tls_key);
    tls_free_server(s);
    free(s);
}

static void config_free(config_t *c)
{
    if (!c)
        return;
    for (int i = 0; i < c->nservers; i++)
        server_free(c->servers[i]);
    free(c->servers);
    free(c->path);
    free(c->text);
    free(c->admin_addr);
    free(c->pidfile);
    free(c);
}

void config_ref(config_t *c)
{
    c->refs++;
}

void config_unref(config_t *c)
{
    if (!c)
        return;
    if (--c->refs <= 0)
        config_free(c);
}

/* ------------------------------------------------------------------ */
/* Interpretation                                                      */
/* ------------------------------------------------------------------ */

static int resolve_upstream(upstream_t *u, int line, char *err, size_t errlen)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", u->port);
    int rc = getaddrinfo(u->host, portstr, &hints, &res);
    if (rc != 0 || !res) {
        if (res)
            freeaddrinfo(res);
        FAIL("line %d: cannot resolve upstream '%s': %s", line, u->hostport, rc ? gai_strerror(rc) : "no address");
    }
    /* prefer IPv4 for predictability when both exist */
    struct addrinfo *pick = res;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next)
        if (ai->ai_family == AF_INET) {
            pick = ai;
            break;
        }
    memcpy(&u->addr, pick->ai_addr, pick->ai_addrlen);
    u->addrlen = pick->ai_addrlen;
    u->resolved = 1;
    freeaddrinfo(res);
    return 0;
}

static int pool_add_upstream(pool_t *p, const char *spec, int line, char *err, size_t errlen)
{
    if (p->nups >= 64)
        FAIL("line %d: at most 64 upstreams per pool", line);
    if (str_has_prefix(spec, "https://"))
        FAIL("line %d: upstream '%s': TLS to upstreams is not supported", line, spec);
    upstream_t *u = xcalloc(1, sizeof *u);
    u->weight = 1;
    if (parse_hostport(spec, &u->host, &u->port, 80) < 0) {
        free(u);
        FAIL("line %d: invalid upstream address '%s'", line, spec);
    }
    if (!*u->host) {
        free(u->host);
        u->host = xstrdup("127.0.0.1");
    }
    char hp[300];
    if (strchr(u->host, ':'))
        snprintf(hp, sizeof hp, "[%s]:%d", u->host, u->port);
    else
        snprintf(hp, sizeof hp, "%s:%d", u->host, u->port);
    u->hostport = xstrdup(hp);
    if (resolve_upstream(u, line, err, errlen) < 0) {
        free(u->host);
        free(u->hostport);
        free(u);
        return -1;
    }
    p->ups = xrealloc(p->ups, sizeof(upstream_t *) * (size_t)(p->nups + 1));
    p->ups[p->nups++] = u;
    return 0;
}

/* Parse "host:port [weight=N] host:port ..." starting at args[from]. */
static int pool_add_upstream_list(pool_t *p, node_t *d, int from, char *err, size_t errlen)
{
    for (int i = from; i < d->nargs; i++) {
        if (str_has_prefix(d->args[i], "weight=")) {
            if (p->nups == 0)
                FAIL("line %d: weight= must follow an upstream", d->line);
            char *end;
            long v = strtol(d->args[i] + 7, &end, 10);
            if (*end || v < 0 || v > 1000)
                FAIL("line %d: invalid weight '%s'", d->line, d->args[i]);
            p->ups[p->nups - 1]->weight = (int)v;
            continue;
        }
        if (pool_add_upstream(p, d->args[i], d->line, err, errlen) < 0)
            return -1;
    }
    return 0;
}

static int add_hdr_op(hdr_op_t **ops, int *n, node_t *d, char *err, size_t errlen)
{
    /* header_up [+|-]Name [value] */
    if (want_args(d, 1, 2, err, errlen) < 0)
        return -1;
    const char *name = d->args[1];
    hdr_op_t op = { 0, NULL, NULL };
    if (name[0] == '-') {
        op.kind = 2;
        name++;
        if (d->nargs > 2)
            FAIL("line %d: '%s -%s' takes no value", d->line, d->args[0], name);
    } else {
        if (name[0] == '+') {
            op.kind = 1;
            name++;
        }
        if (d->nargs < 3)
            FAIL("line %d: '%s %s' needs a value", d->line, d->args[0], d->args[1]);
        op.value = xstrdup(d->args[2]);
    }
    if (!*name)
        FAIL("line %d: '%s': empty header name", d->line, d->args[0]);
    op.name = xstrdup(name);
    *ops = xrealloc(*ops, sizeof(hdr_op_t) * (size_t)(*n + 1));
    (*ops)[(*n)++] = op;
    return 0;
}

static int parse_lb_policy(pool_t *p, node_t *d, char *err, size_t errlen)
{
    if (want_args(d, 1, 3, err, errlen) < 0)
        return -1;
    const char *pol = d->args[1];
    free(p->key.name);
    p->key.name = NULL;
    p->key.src = KS_NONE;
    if (strcaseeq(pol, "round_robin") || strcaseeq(pol, "rr")) {
        p->policy = LB_ROUND_ROBIN;
    } else if (strcaseeq(pol, "least_conn") || strcaseeq(pol, "least_connections")) {
        p->policy = LB_LEAST_CONN;
    } else if (strcaseeq(pol, "random")) {
        p->policy = LB_RANDOM;
    } else if (strcaseeq(pol, "first")) {
        p->policy = LB_FIRST;
    } else if (strcaseeq(pol, "ip_hash")) {
        p->policy = LB_HASH;
        p->key.src = KS_CLIENT_IP;
    } else if (strcaseeq(pol, "uri_hash")) {
        p->policy = LB_HASH;
        p->key.src = KS_URI;
    } else {
        int argi = 1;
        if (strcaseeq(pol, "hash") || strcaseeq(pol, "payload") || strcaseeq(pol, "payload_hash")) {
            argi = 2;
            if (d->nargs <= argi)
                FAIL("line %d: 'lb_policy %s' needs a key source (json, form, body, header, cookie, query, path, client_ip)", d->line, pol);
        }
        int src, named;
        if (parse_keysrc(d->args[argi], &src, &named) < 0)
            FAIL("line %d: unknown lb_policy '%s'", d->line, pol);
        p->policy = LB_HASH;
        p->key.src = src;
        if (named) {
            if (d->nargs <= argi + 1)
                FAIL("line %d: 'lb_policy %s' needs a name (e.g. a field path or header name)", d->line, d->args[argi]);
            p->key.name = xstrdup(d->args[argi + 1]);
        } else if (d->nargs > argi + 1) {
            FAIL("line %d: 'lb_policy %s' takes no name", d->line, d->args[argi]);
        }
    }
    if (p->policy != LB_HASH && d->nargs > 2)
        FAIL("line %d: 'lb_policy %s' takes no arguments", d->line, pol);
    return 0;
}

static int parse_match(route_t *r, node_t *d, char *err, size_t errlen)
{
    /* match [not] <source> [name] [op] [values...] */
    int ai = 1;
    matcher_t m;
    memset(&m, 0, sizeof m);
    if (ai < d->nargs && strcaseeq(d->args[ai], "not")) {
        m.negate = 1;
        ai++;
    }
    if (ai >= d->nargs)
        FAIL("line %d: 'match' needs a source (method, path, host, header, query, cookie, json, form, body, remote_ip)", d->line);
    int named;
    if (parse_keysrc(d->args[ai], &m.key.src, &named) < 0)
        FAIL("line %d: unknown match source '%s'", d->line, d->args[ai]);
    ai++;
    if (named) {
        if (ai >= d->nargs)
            FAIL("line %d: 'match %s' needs a name", d->line, d->args[ai - 1]);
        m.key.name = xstrdup(d->args[ai++]);
    }
    m.op = OP_EQ;
    if (ai < d->nargs && parse_op(d->args[ai], &m.op) == 0)
        ai++;
    int nvals = d->nargs - ai;
    if (m.op == OP_EXISTS || m.op == OP_MISSING) {
        if (nvals)
            FAIL("line %d: 'match ... %s' takes no values", d->line, d->args[ai - 1]);
    } else if (nvals == 0) {
        if (m.op == OP_EQ) {
            m.op = OP_EXISTS;
        } else {
            free(m.key.name);
            FAIL("line %d: 'match' needs at least one value", d->line);
        }
    }
    m.vals = xcalloc((size_t)nvals + 1, sizeof(char *));
    for (int i = 0; i < nvals; i++)
        m.vals[m.nvals++] = xstrdup(d->args[ai + i]);
    if (m.op == OP_RE || m.op == OP_NRE) {
        m.re = xcalloc((size_t)nvals + 1, sizeof(regex_t));
        for (int i = 0; i < nvals; i++) {
            int rc = regcomp(&m.re[i], m.vals[i], REG_EXTENDED | REG_NOSUB);
            if (rc) {
                char rb[128];
                regerror(rc, &m.re[i], rb, sizeof rb);
                snprintf(err, errlen, "line %d: bad regex '%s': %s", d->line, m.vals[i], rb);
                /* free compiled ones so far */
                for (int k = 0; k < i; k++)
                    regfree(&m.re[k]);
                free(m.re);
                m.re = NULL;
                for (int k = 0; k < m.nvals; k++)
                    free(m.vals[k]);
                free(m.vals);
                free(m.key.name);
                return -1;
            }
        }
    }
    if (m.op == OP_GT || m.op == OP_LT || m.op == OP_GE || m.op == OP_LE) {
        m.nums = xcalloc((size_t)nvals + 1, sizeof(double));
        for (int i = 0; i < nvals; i++)
            if (!is_numeric(m.vals[i], &m.nums[i])) {
                snprintf(err, errlen, "line %d: '%s' is not a number", d->line, m.vals[i]);
                matcher_free(&m);
                return -1;
            }
    }
    if (m.key.src == KS_CLIENT_IP && (m.op == OP_EQ || m.op == OP_NE)) {
        for (int i = 0; i < nvals; i++) {
            char tmp[80];
            snprintf(tmp, sizeof tmp, "%s", m.vals[i]);
            char *sl = strchr(tmp, '/');
            if (sl)
                *sl = 0;
            unsigned char b[16];
            if (inet_pton(strchr(tmp, ':') ? AF_INET6 : AF_INET, tmp, b) != 1) {
                snprintf(err, errlen, "line %d: invalid IP or CIDR '%s'", d->line, m.vals[i]);
                matcher_free(&m);
                return -1;
            }
        }
    }
    r->m = xrealloc(r->m, sizeof(matcher_t) * (size_t)(r->nm + 1));
    r->m[r->nm++] = m;
    return 0;
}

static pool_t *pool_new(const char *name)
{
    pool_t *p = xcalloc(1, sizeof *p);
    p->name = xstrdup(name);
    p->policy = LB_ROUND_ROBIN;
    p->retries = 2;
    p->max_fails = 3;
    p->fail_timeout = 10;
    p->health_interval = 10;
    p->health_timeout = 5;
    p->connect_timeout = 5;
    p->response_timeout = 60;
    p->keepalive_idle = 32;
    p->keepalive_timeout = 60;
    p->preserve_host = 1;
    return p;
}

/* Directives shared by `reverse_proxy { }` and `route { }` blocks. */
static int parse_pool_directive(pool_t *p, node_t *d, int *handled, char *err, size_t errlen)
{
    const char *k = d->args[0];
    *handled = 1;
    if (strcaseeq(k, "to") || strcaseeq(k, "upstream") || strcaseeq(k, "upstreams")) {
        if (want_args(d, 1, -1, err, errlen) < 0)
            return -1;
        if (pool_add_upstream_list(p, d, 1, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "lb_policy") || strcaseeq(k, "policy")) {
        return parse_lb_policy(p, d, err, errlen);
    } else if (strcaseeq(k, "lb_retries") || strcaseeq(k, "retries")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || arg_int(d, 1, &p->retries, 0, 64, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "max_fails")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || arg_int(d, 1, &p->max_fails, 0, 1000000, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "fail_timeout") || strcaseeq(k, "fail_duration")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || arg_duration(d, 1, &p->fail_timeout, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "unhealthy_status")) {
        if (want_args(d, 1, 1, err, errlen) < 0)
            return -1;
        if (strcaseeq(d->args[1], "5xx"))
            p->unhealthy_5xx = 1;
        else if (strcaseeq(d->args[1], "none"))
            p->unhealthy_5xx = 0;
        else
            FAIL("line %d: unhealthy_status accepts '5xx' or 'none'", d->line);
    } else if (strcaseeq(k, "health_uri") || strcaseeq(k, "health_path")) {
        if (want_args(d, 1, 1, err, errlen) < 0)
            return -1;
        if (d->args[1][0] != '/')
            FAIL("line %d: health_uri must start with '/'", d->line);
        free(p->health_uri);
        p->health_uri = xstrdup(d->args[1]);
    } else if (strcaseeq(k, "health_interval")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || arg_duration(d, 1, &p->health_interval, err, errlen) < 0)
            return -1;
        if (p->health_interval < 0.1)
            FAIL("line %d: health_interval too small", d->line);
    } else if (strcaseeq(k, "health_timeout")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || arg_duration(d, 1, &p->health_timeout, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "health_status")) {
        if (want_args(d, 1, 1, err, errlen) < 0)
            return -1;
        if (strcaseeq(d->args[1], "2xx") || strcaseeq(d->args[1], "any"))
            p->health_status = 0;
        else if (arg_int(d, 1, &p->health_status, 100, 599, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "health_host")) {
        if (want_args(d, 1, 1, err, errlen) < 0)
            return -1;
        free(p->health_host);
        p->health_host = xstrdup(d->args[1]);
    } else if (strcaseeq(k, "connect_timeout") || strcaseeq(k, "dial_timeout")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || arg_duration(d, 1, &p->connect_timeout, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "response_timeout") || strcaseeq(k, "response_header_timeout")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || arg_duration(d, 1, &p->response_timeout, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "keepalive_idle") || strcaseeq(k, "keepalive_idle_conns")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || arg_int(d, 1, &p->keepalive_idle, 0, 100000, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "keepalive_timeout") || strcaseeq(k, "keepalive")) {
        if (want_args(d, 1, 1, err, errlen) < 0)
            return -1;
        if (strcaseeq(d->args[1], "off")) {
            p->keepalive_idle = 0;
        } else if (arg_duration(d, 1, &p->keepalive_timeout, err, errlen) < 0) {
            return -1;
        }
    } else if (strcaseeq(k, "header_up")) {
        return add_hdr_op(&p->hdr_up, &p->n_hdr_up, d, err, errlen);
    } else if (strcaseeq(k, "header_down")) {
        return add_hdr_op(&p->hdr_down, &p->n_hdr_down, d, err, errlen);
    } else if (strcaseeq(k, "preserve_host")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || arg_bool(d, 1, &p->preserve_host, err, errlen) < 0)
            return -1;
    } else {
        *handled = 0;
    }
    return 0;
}

static int pool_finalize(pool_t *p, int line, char *err, size_t errlen)
{
    if (p->nups == 0)
        FAIL("line %d: '%s' has no upstreams (use 'to host:port ...')", line, p->name);
    p->total_weight = 0;
    for (int i = 0; i < p->nups; i++)
        p->total_weight += p->ups[i]->weight;
    if (p->total_weight <= 0)
        FAIL("line %d: '%s': all upstreams have weight 0", line, p->name);
    if (p->retries > p->nups - 1)
        p->retries = p->nups - 1;
    return 0;
}

static int parse_respond(route_t *r, node_t *d, char *err, size_t errlen)
{
    /* respond [status] [body] */
    r->kind = ROUTE_RESPOND;
    r->resp_status = 200;
    int ai = 1;
    if (ai < d->nargs && is_numeric(d->args[ai], NULL)) {
        if (arg_int(d, ai, &r->resp_status, 100, 599, err, errlen) < 0)
            return -1;
        ai++;
    }
    if (ai < d->nargs) {
        free(r->resp_body);
        r->resp_body = xstrdup(d->args[ai++]);
    }
    if (ai < d->nargs)
        FAIL("line %d: 'respond' accepts [status] [body]", d->line);
    return 0;
}

static int parse_redirect(route_t *r, node_t *d, char *err, size_t errlen)
{
    /* redir <location> [code] */
    if (want_args(d, 1, 2, err, errlen) < 0)
        return -1;
    r->kind = ROUTE_REDIRECT;
    r->resp_status = 302;
    free(r->resp_body);
    r->resp_body = xstrdup(d->args[1]);
    if (d->nargs > 2 && arg_int(d, 2, &r->resp_status, 300, 399, err, errlen) < 0)
        return -1;
    return 0;
}

static int parse_route(server_t *s, node_t *d, char *err, size_t errlen)
{
    route_t *r = xcalloc(1, sizeof *r);
    char name[64];
    if (d->nargs > 2) {
        free(r);
        FAIL("line %d: 'route [name] {' takes at most one argument", d->line);
    }
    if (d->nargs == 2)
        snprintf(name, sizeof name, "%s", d->args[1]);
    else
        snprintf(name, sizeof name, "route%d", s->nroutes + 1);
    r->name = xstrdup(name);
    r->kind = -1;
    pool_t *p = pool_new(name);
    for (int i = 0; i < d->nkids; i++) {
        node_t *c = d->kids[i];
        const char *k = c->args[0];
        int handled = 0;
        if (strcaseeq(k, "match")) {
            if (parse_match(r, c, err, errlen) < 0)
                goto fail;
        } else if (strcaseeq(k, "respond")) {
            if (r->kind >= 0 && r->kind != ROUTE_RESPOND) {
                snprintf(err, errlen, "line %d: route has more than one handler", c->line);
                goto fail;
            }
            if (parse_respond(r, c, err, errlen) < 0)
                goto fail;
        } else if (strcaseeq(k, "redir") || strcaseeq(k, "redirect")) {
            if (r->kind >= 0) {
                snprintf(err, errlen, "line %d: route has more than one handler", c->line);
                goto fail;
            }
            if (parse_redirect(r, c, err, errlen) < 0)
                goto fail;
        } else if (strcaseeq(k, "reverse_proxy")) {
            /* inline upstream list and nested options */
            if (pool_add_upstream_list(p, c, 1, err, errlen) < 0)
                goto fail;
            for (int j = 0; j < c->nkids; j++) {
                int h2 = 0;
                if (parse_pool_directive(p, c->kids[j], &h2, err, errlen) < 0)
                    goto fail;
                if (!h2) {
                    snprintf(err, errlen, "line %d: unknown reverse_proxy option '%s'", c->kids[j]->line, c->kids[j]->args[0]);
                    goto fail;
                }
            }
            r->kind = ROUTE_PROXY;
        } else {
            if (parse_pool_directive(p, c, &handled, err, errlen) < 0)
                goto fail;
            if (!handled) {
                snprintf(err, errlen, "line %d: unknown directive '%s' in route", c->line, k);
                goto fail;
            }
            if (strcaseeq(k, "to") || strcaseeq(k, "upstream") || strcaseeq(k, "upstreams")) {
                if (r->kind >= 0 && r->kind != ROUTE_PROXY) {
                    snprintf(err, errlen, "line %d: route has more than one handler", c->line);
                    goto fail;
                }
                r->kind = ROUTE_PROXY;
            }
        }
    }
    if (r->kind < 0) {
        snprintf(err, errlen, "line %d: route '%s' has no handler (to, respond, redir)", d->line, name);
        goto fail;
    }
    if (r->kind == ROUTE_PROXY) {
        if (pool_finalize(p, d->line, err, errlen) < 0)
            goto fail;
        r->pool = p;
    } else {
        /* header_down on respond routes */
        r->hdr_down = p->hdr_down;
        r->n_hdr_down = p->n_hdr_down;
        p->hdr_down = NULL;
        p->n_hdr_down = 0;
        pool_free(p);
    }
    s->routes = xrealloc(s->routes, sizeof(route_t *) * (size_t)(s->nroutes + 1));
    s->routes[s->nroutes++] = r;
    return 0;
fail:
    pool_free(p);
    r->pool = NULL;
    route_free(r);
    return -1;
}

static int parse_reverse_proxy(server_t *s, node_t *d, char *err, size_t errlen)
{
    /* reverse_proxy [upstreams...] [{ options }] - a catch-all route */
    char name[64];
    snprintf(name, sizeof name, "reverse_proxy%d", s->nroutes + 1);
    route_t *r = xcalloc(1, sizeof *r);
    r->name = xstrdup(name);
    r->kind = ROUTE_PROXY;
    pool_t *p = pool_new(name);
    if (pool_add_upstream_list(p, d, 1, err, errlen) < 0)
        goto fail;
    for (int i = 0; i < d->nkids; i++) {
        int handled = 0;
        node_t *c = d->kids[i];
        if (strcaseeq(c->args[0], "match")) {
            if (parse_match(r, c, err, errlen) < 0)
                goto fail;
            continue;
        }
        if (parse_pool_directive(p, c, &handled, err, errlen) < 0)
            goto fail;
        if (!handled) {
            snprintf(err, errlen, "line %d: unknown reverse_proxy option '%s'", c->line, c->args[0]);
            goto fail;
        }
    }
    if (pool_finalize(p, d->line, err, errlen) < 0)
        goto fail;
    r->pool = p;
    s->routes = xrealloc(s->routes, sizeof(route_t *) * (size_t)(s->nroutes + 1));
    s->routes[s->nroutes++] = r;
    return 0;
fail:
    pool_free(p);
    route_free(r);
    return -1;
}

static server_t *server_new(void)
{
    server_t *s = xcalloc(1, sizeof *s);
    s->max_body = 8 * 1024 * 1024;
    s->read_timeout = 30;
    s->idle_timeout = 120;
    return s;
}

static int parse_server(config_t *cfg, node_t *d, char *err, size_t errlen)
{
    server_t *s = server_new();
    for (int i = 0; i < d->nargs; i++) {
        char *a = xstrdup(d->args[i]);
        size_t l = strlen(a);
        while (l && a[l - 1] == ',')
            a[--l] = 0;
        if (!l) {
            free(a);
            continue;
        }
        const char *addr = a;
        if (str_has_prefix(addr, "https://")) {
            s->tls_cert = s->tls_cert ? s->tls_cert : xstrdup("");
            addr += 8;
        } else if (str_has_prefix(addr, "http://")) {
            addr += 7;
        }
        char *h;
        int port;
        if (parse_hostport(addr, &h, &port, 0) < 0) {
            free(a);
            server_free(s);
            FAIL("line %d: invalid listen address '%s' (use host:port or :port)", d->line, d->args[i]);
        }
        free(h);
        s->addrs = xrealloc(s->addrs, sizeof(char *) * (size_t)(s->naddr + 1));
        s->addrs[s->naddr++] = xstrdup(addr);
        free(a);
    }
    if (s->naddr == 0) {
        server_free(s);
        FAIL("line %d: server block has no listen address", d->line);
    }
    for (int i = 0; i < d->nkids; i++) {
        node_t *c = d->kids[i];
        const char *k = c->args[0];
        int rc = 0;
        if (strcaseeq(k, "route")) {
            rc = parse_route(s, c, err, errlen);
        } else if (strcaseeq(k, "reverse_proxy")) {
            rc = parse_reverse_proxy(s, c, err, errlen);
        } else if (strcaseeq(k, "respond")) {
            route_t *r = xcalloc(1, sizeof *r);
            char name[64];
            snprintf(name, sizeof name, "respond%d", s->nroutes + 1);
            r->name = xstrdup(name);
            rc = parse_respond(r, c, err, errlen);
            if (rc < 0) {
                route_free(r);
            } else {
                s->routes = xrealloc(s->routes, sizeof(route_t *) * (size_t)(s->nroutes + 1));
                s->routes[s->nroutes++] = r;
            }
        } else if (strcaseeq(k, "max_body") || strcaseeq(k, "max_body_size") || strcaseeq(k, "request_body")) {
            if ((rc = want_args(c, 1, 1, err, errlen)) == 0 && parse_size(c->args[1], &s->max_body) < 0) {
                snprintf(err, errlen, "line %d: invalid size '%s'", c->line, c->args[1]);
                rc = -1;
            }
        } else if (strcaseeq(k, "read_timeout")) {
            if ((rc = want_args(c, 1, 1, err, errlen)) == 0)
                rc = arg_duration(c, 1, &s->read_timeout, err, errlen);
        } else if (strcaseeq(k, "idle_timeout")) {
            if ((rc = want_args(c, 1, 1, err, errlen)) == 0)
                rc = arg_duration(c, 1, &s->idle_timeout, err, errlen);
        } else if (strcaseeq(k, "log") || strcaseeq(k, "access_log")) {
            s->access_log = 1;
            if (c->nargs > 1)
                rc = arg_bool(c, 1, &s->access_log, err, errlen);
        } else if (strcaseeq(k, "tls")) {
            if ((rc = want_args(c, 2, 2, err, errlen)) == 0) {
                free(s->tls_cert);
                free(s->tls_key);
                s->tls_cert = xstrdup(c->args[1]);
                s->tls_key = xstrdup(c->args[2]);
            }
        } else {
            snprintf(err, errlen, "line %d: unknown directive '%s'", c->line, k);
            rc = -1;
        }
        if (rc < 0) {
            server_free(s);
            return -1;
        }
    }
    if (s->tls_cert && !*s->tls_cert) {
        server_free(s);
        FAIL("line %d: https:// listener requires 'tls <cert> <key>'", d->line);
    }
    if (s->tls_cert && tls_init_server(s, err, errlen) < 0) {
        server_free(s);
        return -1;
    }
    if (s->nroutes == 0) {
        server_free(s);
        FAIL("line %d: server block has no handlers (reverse_proxy, route, respond)", d->line);
    }
    cfg->servers = xrealloc(cfg->servers, sizeof(server_t *) * (size_t)(cfg->nservers + 1));
    cfg->servers[cfg->nservers++] = s;
    return 0;
}

static int parse_global(config_t *cfg, node_t *d, char *err, size_t errlen)
{
    for (int i = 0; i < d->nkids; i++) {
        node_t *c = d->kids[i];
        const char *k = c->args[0];
        if (strcaseeq(k, "workers")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            if (strcaseeq(c->args[1], "auto"))
                cfg->workers = 0;
            else if (arg_int(c, 1, &cfg->workers, 1, 1024, err, errlen) < 0)
                return -1;
        } else if (strcaseeq(k, "admin")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            free(cfg->admin_addr);
            cfg->admin_addr = strcaseeq(c->args[1], "off") ? NULL : xstrdup(c->args[1]);
        } else if (strcaseeq(k, "log_level") || strcaseeq(k, "log")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            const char *lv = c->args[1];
            if (strcaseeq(lv, "debug")) cfg->log_level = LOG_DEBUG;
            else if (strcaseeq(lv, "info")) cfg->log_level = LOG_INFO;
            else if (strcaseeq(lv, "warn") || strcaseeq(lv, "warning")) cfg->log_level = LOG_WARN;
            else if (strcaseeq(lv, "error")) cfg->log_level = LOG_ERROR;
            else FAIL("line %d: unknown log level '%s'", c->line, lv);
        } else if (strcaseeq(k, "pidfile")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            free(cfg->pidfile);
            cfg->pidfile = xstrdup(c->args[1]);
        } else if (strcaseeq(k, "grace") || strcaseeq(k, "grace_period")) {
            if (want_args(c, 1, 1, err, errlen) < 0 || arg_duration(c, 1, &cfg->grace, err, errlen) < 0)
                return -1;
        } else {
            FAIL("line %d: unknown global option '%s'", c->line, k);
        }
    }
    return 0;
}

config_t *config_parse(const char *text, const char *path, char *err, size_t errlen)
{
    toks_t t = { NULL, 0, 0 };
    err[0] = 0;
    if (tokenize(text, &t, err, errlen) < 0) {
        toks_free(&t);
        return NULL;
    }
    node_t *root = xcalloc(1, sizeof *root);
    int i = 0;
    if (parse_block(&t, &i, root, 0, err, errlen) < 0) {
        node_free(root);
        toks_free(&t);
        return NULL;
    }
    toks_free(&t);

    config_t *cfg = xcalloc(1, sizeof *cfg);
    cfg->refs = 1;
    cfg->workers = 1;
    cfg->log_level = LOG_INFO;
    cfg->grace = 10;
    cfg->path = xstrdup(path ? path : "<inline>");
    cfg->text = xstrdup(text);

    for (int k = 0; k < root->nkids; k++) {
        node_t *d = root->kids[k];
        int rc;
        if (d->nargs == 0) {
            if (k != 0) {
                snprintf(err, errlen, "line %d: global options block must come first", d->line);
                rc = -1;
            } else {
                rc = parse_global(cfg, d, err, errlen);
            }
        } else {
            rc = parse_server(cfg, d, err, errlen);
        }
        if (rc < 0) {
            node_free(root);
            config_unref(cfg);
            return NULL;
        }
    }
    node_free(root);
    if (cfg->nservers == 0) {
        snprintf(err, errlen, "no server blocks defined");
        config_unref(cfg);
        return NULL;
    }
    if (cfg->admin_addr) {
        /* the admin API is a built-in server with its own handler */
        server_t *s = server_new();
        s->is_admin = 1;
        s->addrs = xmalloc(sizeof(char *));
        s->addrs[0] = xstrdup(cfg->admin_addr);
        s->naddr = 1;
        cfg->servers = xrealloc(cfg->servers, sizeof(server_t *) * (size_t)(cfg->nservers + 1));
        cfg->servers[cfg->nservers++] = s;
    }
    return cfg;
}

config_t *config_load(const char *path, char *err, size_t errlen)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return NULL;
    }
    buf_t b;
    buf_init(&b);
    char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0)
        buf_append(&b, tmp, n);
    fclose(f);
    buf_append(&b, "", 1);
    config_t *cfg = config_parse(b.data, path, err, errlen);
    buf_free(&b);
    return cfg;
}
