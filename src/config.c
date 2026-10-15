/*
 * config.c - Limerfile parser.
 *
 * The syntax follows the Caddyfile conventions: whitespace-separated tokens,
 * one directive per line, blocks delimited by '{' at the end of a line and
 * '}' on its own line, '#' comments, quoted strings, {$ENV} substitution,
 * snippets "(name) { ... }" and "import <file|snippet>".
 */
#include "limer.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <libgen.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

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

/* Replace {$VAR} and {$VAR:default} with environment values. */
static char *expand_env(const char *in)
{
    buf_t b;
    buf_init(&b);
    const char *p = in;
    while (*p) {
        if (p[0] == '{' && p[1] == '$') {
            const char *end = strchr(p, '}');
            if (end) {
                size_t n = (size_t)(end - p - 2);
                char name[256];
                if (n < sizeof name) {
                    memcpy(name, p + 2, n);
                    name[n] = 0;
                    char *def = strchr(name, ':');
                    if (def)
                        *def++ = 0;
                    const char *v = getenv(name);
                    if (!v)
                        v = def ? def : "";
                    buf_puts(&b, v);
                    p = end + 1;
                    continue;
                }
            }
        }
        buf_append(&b, p, 1);
        p++;
    }
    buf_append(&b, "", 1);
    char *out = xstrdup(b.data);
    buf_free(&b);
    return out;
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

static node_t *node_clone(const node_t *n)
{
    node_t *c = xcalloc(1, sizeof *c);
    c->line = n->line;
    c->args = xcalloc((size_t)n->nargs + 1, sizeof(char *));
    for (int i = 0; i < n->nargs; i++)
        c->args[c->nargs++] = xstrdup(n->args[i]);
    c->kids = xcalloc((size_t)n->nkids + 1, sizeof(node_t *));
    for (int i = 0; i < n->nkids; i++)
        c->kids[c->nkids++] = node_clone(n->kids[i]);
    return c;
}

static void node_add_kid(node_t *parent, node_t *kid)
{
    parent->kids = xrealloc(parent->kids, sizeof(node_t *) * (size_t)(parent->nkids + 1));
    parent->kids[parent->nkids++] = kid;
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
        if (d->nargs == 0 && nested) {
            snprintf(err, errlen, "line %d: unexpected '{' (a block needs a directive name)", d->line);
            node_free(d);
            return -1;
        }
        node_add_kid(parent, d);
    }
    if (nested) {
        snprintf(err, errlen, "unexpected end of file: missing '}'");
        return -1;
    }
    return 0;
}

static node_t *parse_text_to_tree(const char *text, char *err, size_t errlen)
{
    toks_t t = { NULL, 0, 0 };
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
    return root;
}

/* ------------------------------------------------------------------ */
/* Imports and snippets                                                */
/* ------------------------------------------------------------------ */

typedef struct snippets {
    char **names;
    node_t **bodies;
    int n;
} snippets_t;

static char *read_file(const char *path, char *err, size_t errlen)
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
    char *text = xstrdup(b.data);
    buf_free(&b);
    return text;
}

/* substitute {args.N} in a cloned snippet */
static void subst_args(node_t *n, char **args, int nargs)
{
    for (int i = 0; i < n->nargs; i++) {
        const char *a = n->args[i];
        const char *m = strstr(a, "{args.");
        if (!m)
            continue;
        buf_t b;
        buf_init(&b);
        const char *p = a;
        while (*p) {
            if (str_has_prefix(p, "{args.")) {
                char *end;
                long idx = strtol(p + 6, &end, 10);
                if (*end == '}' && idx >= 0) {
                    if (idx < nargs)
                        buf_puts(&b, args[idx]);
                    p = end + 1;
                    continue;
                }
            }
            buf_append(&b, p++, 1);
        }
        buf_append(&b, "", 1);
        free(n->args[i]);
        n->args[i] = xstrdup(b.data);
        buf_free(&b);
    }
    for (int i = 0; i < n->nkids; i++)
        subst_args(n->kids[i], args, nargs);
}

static int expand_imports(node_t *parent, const char *base_dir, snippets_t *sn, int depth, char *err, size_t errlen);

static int import_file(node_t *parent, int *pos, const char *path, const char *base_dir, snippets_t *sn, int depth, char *err, size_t errlen)
{
    char *text = read_file(path, err, errlen);
    if (!text)
        return -1;
    char *expanded = expand_env(text);
    free(text);
    char ierr[512];
    node_t *tree = parse_text_to_tree(expanded, ierr, sizeof ierr);
    free(expanded);
    if (!tree) {
        snprintf(err, errlen, "%s: %s", path, ierr);
        return -1;
    }
    char *dup = xstrdup(path);
    const char *dir = dirname(dup);
    int rc = expand_imports(tree, dir, sn, depth + 1, err, errlen);
    free(dup);
    if (rc < 0) {
        node_free(tree);
        return -1;
    }
    /* splice tree->kids into parent at *pos */
    int k = tree->nkids;
    parent->kids = xrealloc(parent->kids, sizeof(node_t *) * (size_t)(parent->nkids + k));
    memmove(parent->kids + *pos + k, parent->kids + *pos, sizeof(node_t *) * (size_t)(parent->nkids - *pos));
    for (int i = 0; i < k; i++)
        parent->kids[*pos + i] = tree->kids[i];
    parent->nkids += k;
    *pos += k;
    tree->nkids = 0;
    node_free(tree);
    return 0;
}

static int expand_imports(node_t *parent, const char *base_dir, snippets_t *sn, int depth, char *err, size_t errlen)
{
    if (depth > 10) {
        snprintf(err, errlen, "import nesting too deep");
        return -1;
    }
    for (int i = 0; i < parent->nkids;) {
        node_t *d = parent->kids[i];
        if (d->nargs == 0 || strcmp(d->args[0], "import") != 0) {
            if (expand_imports(d, base_dir, sn, depth, err, errlen) < 0)
                return -1;
            i++;
            continue;
        }
        if (d->nargs < 2) {
            snprintf(err, errlen, "line %d: import needs a file or snippet name", d->line);
            return -1;
        }
        const char *what = d->args[1];
        /* remove the import node */
        memmove(parent->kids + i, parent->kids + i + 1, sizeof(node_t *) * (size_t)(parent->nkids - i - 1));
        parent->nkids--;
        int snip = -1;
        for (int k = 0; k < sn->n; k++)
            if (strcmp(sn->names[k], what) == 0)
                snip = k;
        if (snip >= 0) {
            node_t *body = node_clone(sn->bodies[snip]);
            subst_args(body, d->args + 2, d->nargs - 2);
            int k = body->nkids;
            parent->kids = xrealloc(parent->kids, sizeof(node_t *) * (size_t)(parent->nkids + k));
            memmove(parent->kids + i + k, parent->kids + i, sizeof(node_t *) * (size_t)(parent->nkids - i));
            for (int j = 0; j < k; j++)
                parent->kids[i + j] = body->kids[j];
            parent->nkids += k;
            body->nkids = 0;
            node_free(body);
            /* expanded snippet may itself contain imports */
            node_free(d);
            continue;
        }
        char pattern[4096];
        if (what[0] == '/')
            snprintf(pattern, sizeof pattern, "%s", what);
        else
            snprintf(pattern, sizeof pattern, "%s/%s", base_dir, what);
        glob_t g;
        memset(&g, 0, sizeof g);
        int rc = glob(pattern, 0, NULL, &g);
        if (rc != 0 || g.gl_pathc == 0) {
            globfree(&g);
            if (strpbrk(what, "*?[")) {
                node_free(d);
                continue; /* a glob matching nothing imports nothing */
            }
            snprintf(err, errlen, "line %d: import: no such file or snippet '%s'", d->line, what);
            node_free(d);
            return -1;
        }
        int pos = i;
        for (size_t f = 0; f < g.gl_pathc; f++) {
            if (import_file(parent, &pos, g.gl_pathv[f], base_dir, sn, depth, err, errlen) < 0) {
                globfree(&g);
                node_free(d);
                return -1;
            }
        }
        globfree(&g);
        node_free(d);
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
        { "tls_client", KS_TLS_CLIENT, 1 }, { "client_cert", KS_TLS_CLIENT, 1 },
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
    free(m->split_key.name);
}

static void hdr_ops_free(hdr_op_t *ops, int n)
{
    for (int i = 0; i < n; i++) {
        free(ops[i].name);
        free(ops[i].value);
    }
    free(ops);
}

static void auth_free(basic_auth_t *a)
{
    if (!a)
        return;
    for (int i = 0; i < a->nusers; i++) {
        free(a->users[i].name);
        free(a->users[i].hash);
    }
    free(a->users);
    free(a->realm);
    free(a);
}

static void rl_cfg_free(rate_limit_cfg_t *r)
{
    if (!r)
        return;
    free(r->name);
    free(r->key);
    ratelimit_free(r->rl);
    free(r);
}

static void files_free(file_server_t *f)
{
    if (!f)
        return;
    free(f->root);
    for (int i = 0; i < f->nindex; i++)
        free(f->index[i]);
    free(f->index);
    for (int i = 0; i < f->ntry; i++)
        free(f->try_files[i]);
    free(f->try_files);
    free(f);
}

static void pool_free(pool_t *p)
{
    if (!p)
        return;
    for (int i = 0; i < p->nups; i++)
        upstream_free(p->ups[i]);
    free(p->ups);
    for (int i = 0; i < p->nretired; i++)
        upstream_free(p->retired[i]);
    free(p->retired);
    free(p->dyn_name);
    for (int i = 0; i < p->ndiscover_allow; i++)
        free(p->discover_allow[i]);
    free(p->discover_allow);
    if (p->mirror)
        pool_free(p->mirror);
    free(p->name);
    free(p->key.name);
    free(p->health_uri);
    free(p->health_host);
    free(p->retry_status);
    free(p->redirect_status);
    free(p->redirect_to);
    hdr_ops_free(p->hdr_up, p->n_hdr_up);
    hdr_ops_free(p->hdr_down, p->n_hdr_down);
    free(p->tls_server_name);
    free(p->tls_ca);
    free(p->tls_client_cert);
    free(p->tls_client_key);
    tls_free_pool_client(p);
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
    for (int i = 0; i < r->nrw; i++) {
        free(r->rw[i].a);
        free(r->rw[i].b);
    }
    free(r->rw);
    auth_free(r->auth);
    files_free(r->files);
    rl_cfg_free(r->rl);
    free(r->cache);
    free(r);
}

static void server_free(server_t *s)
{
    if (!s)
        return;
    for (int i = 0; i < s->naddr; i++)
        free(s->addrs[i]);
    free(s->addrs);
    for (int i = 0; i < s->nhosts; i++)
        free(s->hosts[i]);
    free(s->hosts);
    for (int i = 0; i < s->nroutes; i++)
        route_free(s->routes[i]);
    free(s->routes);
    for (int i = 0; i < s->nclient_ca; i++)
        free(s->client_ca[i]);
    free(s->client_ca);
    free(s->tls_cert);
    free(s->tls_key);
    hdr_ops_free(s->hdr_down, s->n_hdr_down);
    hdr_ops_free(s->hdr_up, s->n_hdr_up);
    auth_free(s->auth);
    rl_cfg_free(s->rl);
    free(s->cache);
    free(s->encode);
    if (s->log_fd > 2)
        close(s->log_fd);
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
    free(c->admin.secret);
    free(c->pidfile);
    free(c->storage);
    free(c->acme_ca);
    free(c->acme_ca_root);
    free(c->acme_email);
    free(c->acme_dns_script);
    for (int i = 0; i < c->nresolvers; i++)
        free(c->resolvers[i]);
    free(c->resolvers);
    for (int i = 0; i < c->ntrusted_proxies; i++)
        free(c->trusted_proxies[i]);
    free(c->trusted_proxies);
    free(c->server_header);
    free(c->scale_up.exec);
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
/* Upstreams and pools                                                 */
/* ------------------------------------------------------------------ */

static const config_t *g_loading_cfg; /* set while config_parse_in runs */
int config_lenient_resolve;
int config_no_dns;

static int resolve_failed(upstream_t *u, int line, const char *detail, char *err, size_t errlen)
{
    if (config_lenient_resolve) {
        LOGW("line %d: cannot resolve upstream '%s' (%s); keeping its previous address", line, u->hostport, detail);
        u->resolved = 0;
        u->addrlen = 0;
        return 0;
    }
    snprintf(err, errlen, "line %d: cannot resolve upstream '%s': %s", line, u->hostport, detail);
    return -1;
}

void resolve_job_init(resolve_job_t *job, const config_t *cfg, int kind, const char *name, int port)
{
    memset(job, 0, sizeof *job);
    job->kind = kind;
    snprintf(job->name, sizeof job->name, "%s", name);
    job->port = port;
    for (int i = 0; cfg && i < cfg->nresolvers && i < 4; i++) {
        snprintf(job->resolvers[i], sizeof job->resolvers[i], "%s", cfg->resolvers[i]);
        job->nresolvers++;
    }
}

static int resolve_upstream(upstream_t *u, int line, char *err, size_t errlen)
{
    if (config_no_dns && !is_ip_literal(u->host)) {
        u->resolved = 0;
        u->addrlen = 0;
        return 0;
    }
    if (g_loading_cfg && g_loading_cfg->nresolvers && !is_ip_literal(u->host)) {
        /* named upstreams go through the configured resolvers */
        resolve_job_t *job = xcalloc(1, sizeof *job);
        resolve_job_init(job, g_loading_cfg, RESOLVE_ADDR, u->host, u->port);
        resolve_sync(job);
        if (job->nres == 0) {
            int rc = resolve_failed(u, line, job->err[0] ? job->err : "no address", err, errlen);
            free(job);
            return rc;
        }
        int pick = 0;
        for (int i = 0; i < job->nres; i++)
            if (job->res[i].addr.ss_family == AF_INET) {
                pick = i;
                break;
            }
        memcpy(&u->addr, &job->res[pick].addr, job->res[pick].len);
        u->addrlen = job->res[pick].len;
        u->resolved = 1;
        free(job);
        return 0;
    }
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
        return resolve_failed(u, line, rc ? gai_strerror(rc) : "no address", err, errlen);
    }
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
    upstream_t *u = xcalloc(1, sizeof *u);
    u->weight = 1;
    if (str_has_prefix(spec, "https://")) {
        u->tls = 1;
        spec += 8;
    } else if (str_has_prefix(spec, "h2c://")) {
        u->h2 = 1;
        spec += 6;
    } else if (str_has_prefix(spec, "h2://")) {
        u->h2 = 1;
        u->tls = 1;
        spec += 5;
    }
    if (parse_hostport(spec, &u->host, &u->port, u->tls ? 443 : 80) < 0) {
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
    snprintf(u->sticky_id, sizeof u->sticky_id, "%016llx", (unsigned long long)hash64(hp, strlen(hp)));
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

/* header_up / header / request_header: [+|-]Name [value], or a block of them */
static int add_hdr_op_args(hdr_op_t **ops, int *n, node_t *d, int from, char *err, size_t errlen)
{
    if (d->nargs <= from)
        FAIL("line %d: '%s' needs a header name", d->line, d->args[0]);
    const char *name = d->args[from];
    hdr_op_t op = { 0, NULL, NULL };
    if (name[0] == '-') {
        op.kind = 2;
        name++;
        if (d->nargs > from + 1)
            FAIL("line %d: '%s -%s' takes no value", d->line, d->args[0], name);
    } else {
        if (name[0] == '+') {
            op.kind = 1;
            name++;
        }
        if (d->nargs < from + 2)
            FAIL("line %d: '%s %s' needs a value", d->line, d->args[0], d->args[from]);
        if (d->nargs > from + 2)
            FAIL("line %d: '%s': too many arguments (quote values with spaces)", d->line, d->args[0]);
        op.value = xstrdup(d->args[from + 1]);
    }
    if (!*name)
        FAIL("line %d: '%s': empty header name", d->line, d->args[0]);
    op.name = xstrdup(name);
    *ops = xrealloc(*ops, sizeof(hdr_op_t) * (size_t)(*n + 1));
    (*ops)[(*n)++] = op;
    return 0;
}

static int add_hdr_ops(hdr_op_t **ops, int *n, node_t *d, char *err, size_t errlen)
{
    if (d->nargs > 1) {
        if (add_hdr_op_args(ops, n, d, 1, err, errlen) < 0)
            return -1;
    }
    for (int i = 0; i < d->nkids; i++) {
        node_t *k = d->kids[i];
        /* inside a block each line is "[+|-]Name [value]" */
        node_t tmp = *k;
        char *args[4];
        args[0] = d->args[0];
        int na = 1;
        for (int a = 0; a < k->nargs && na < 4; a++)
            args[na++] = k->args[a];
        tmp.args = args;
        tmp.nargs = na;
        tmp.nkids = 0;
        if (add_hdr_op_args(ops, n, &tmp, 1, err, errlen) < 0)
            return -1;
    }
    if (d->nargs == 1 && d->nkids == 0)
        FAIL("line %d: '%s' needs a header name or a block", d->line, d->args[0]);
    return 0;
}

static int parse_lb_policy(pool_t *p, node_t *d, char *err, size_t errlen)
{
    if (want_args(d, 1, 4, err, errlen) < 0)
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
    } else if (strcaseeq(pol, "sticky_cookie") || strcaseeq(pol, "cookie_sticky")) {
        if (d->nargs > 3)
            FAIL("line %d: 'lb_policy %s' takes at most a cookie name", d->line, pol);
        p->policy = LB_STICKY;
        p->key.src = KS_COOKIE;
        p->key.name = xstrdup(d->nargs > 2 ? d->args[2] : "lb");
        return 0;
    } else if (strcaseeq(pol, "cookie")) {
        /* Caddy's `lb_policy cookie [name [secret]]`: same sticky sessions, Caddy's default name;
         * the secret only shapes Caddy's cookie value and is accepted and ignored. */
        p->policy = LB_STICKY;
        p->key.src = KS_COOKIE;
        p->key.name = xstrdup(d->nargs > 2 ? d->args[2] : "lb");
        return 0;
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
    p->keepalive_idle = 256;
    p->keepalive_timeout = 60;
    p->preserve_host = 1;
    p->refresh = 30;
    p->mirror_sample = 100;
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
    } else if (strcaseeq(k, "retry_status") || strcaseeq(k, "retry_on_status")) {
        /* retry_status 404 503 ... */
        if (want_args(d, 1, 16, err, errlen) < 0)
            return -1;
        for (int i = 1; i < d->nargs; i++) {
            int code;
            if (arg_int(d, i, &code, 200, 599, err, errlen) < 0)
                return -1;
            p->retry_status = xrealloc(p->retry_status, sizeof(int) * (size_t)(p->nretry_status + 1));
            p->retry_status[p->nretry_status++] = code;
        }
    } else if (strcaseeq(k, "redirect_on") || strcaseeq(k, "redirect_status")) {
        /* redirect_on 404 [410 ...] <target> [code|permanent|temporary] */
        int i = 1;
        while (i < d->nargs && strlen(d->args[i]) == 3 && isdigit((unsigned char)d->args[i][0]) &&
               isdigit((unsigned char)d->args[i][1]) && isdigit((unsigned char)d->args[i][2])) {
            int code = atoi(d->args[i]);
            if (code < 200 || code > 599)
                FAIL("line %d: redirect_on: %d is not a response status", d->line, code);
            p->redirect_status = xrealloc(p->redirect_status, sizeof(int) * (size_t)(p->nredirect_status + 1));
            p->redirect_status[p->nredirect_status++] = code;
            i++;
        }
        if (p->nredirect_status == 0 || i >= d->nargs)
            FAIL("line %d: redirect_on needs one or more statuses and a target, e.g. 'redirect_on 404 /'", d->line);
        free(p->redirect_to);
        p->redirect_to = xstrdup(d->args[i++]);
        p->redirect_code = 302;
        if (i < d->nargs) {
            const char *c = d->args[i++];
            if (strcaseeq(c, "permanent"))
                p->redirect_code = 301;
            else if (strcaseeq(c, "temporary"))
                p->redirect_code = 302;
            else if (atoi(c) >= 300 && atoi(c) <= 308)
                p->redirect_code = atoi(c);
            else
                FAIL("line %d: redirect_on: '%s' is not a redirect code", d->line, c);
        }
        if (i < d->nargs)
            FAIL("line %d: redirect_on: unexpected '%s'", d->line, d->args[i]);
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
        if (strcaseeq(d->args[1], "off"))
            p->keepalive_idle = 0;
        else if (arg_duration(d, 1, &p->keepalive_timeout, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "header_up") || strcaseeq(k, "request_header")) {
        return add_hdr_ops(&p->hdr_up, &p->n_hdr_up, d, err, errlen);
    } else if (strcaseeq(k, "header_down")) {
        return add_hdr_ops(&p->hdr_down, &p->n_hdr_down, d, err, errlen);
    } else if (strcaseeq(k, "preserve_host")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || arg_bool(d, 1, &p->preserve_host, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "mirror")) {
        /* mirror <upstreams...> [{ sample <pct>; ... }] : shadow a copy of the request */
        if (p->mirror)
            FAIL("line %d: only one mirror per reverse_proxy", d->line);
        pool_t *mp = pool_new(p->name);
        if (d->nargs > 1 && pool_add_upstream_list(mp, d, 1, err, errlen) < 0) {
            pool_free(mp);
            return -1;
        }
        for (int i = 0; i < d->nkids; i++) {
            node_t *kk = d->kids[i];
            int mh = 0;
            if (strcaseeq(kk->args[0], "sample")) {
                if (want_args(kk, 1, 1, err, errlen) < 0 || !is_numeric(kk->args[1], &p->mirror_sample) ||
                    p->mirror_sample < 0 || p->mirror_sample > 100) {
                    pool_free(mp);
                    FAIL("line %d: mirror sample needs a percentage 0..100", kk->line);
                }
            } else if (parse_pool_directive(mp, kk, &mh, err, errlen) < 0 || !mh) {
                pool_free(mp);
                FAIL("line %d: unknown mirror option '%s'", kk->line, kk->args[0]);
            }
        }
        p->mirror = mp;
    } else if (strcaseeq(k, "mirror_sample")) {
        if (want_args(d, 1, 1, err, errlen) < 0 || !is_numeric(d->args[1], &p->mirror_sample) ||
            p->mirror_sample < 0 || p->mirror_sample > 100)
            FAIL("line %d: mirror_sample needs a percentage 0..100", d->line);
    } else if (strcaseeq(k, "tls")) {
        /* `tls` inside a transport block: use TLS for every upstream of the pool */
        if (d->nargs > 1)
            FAIL("line %d: 'tls' takes no arguments here", d->line);
        for (int i = 0; i < p->nups; i++)
            p->ups[i]->tls = 1;
        p->tls_all = 1;
    } else if (strcaseeq(k, "dynamic")) {
        /* dynamic a <name> <port> [{ refresh <dur> }]  |  dynamic srv <name> [{ refresh <dur> }] */
        if (d->nargs < 3)
            FAIL("line %d: dynamic needs 'a <name> <port>' or 'srv <name>'", d->line);
        if (p->dyn_kind)
            FAIL("line %d: only one 'dynamic' source per pool", d->line);
        if (strcaseeq(d->args[1], "a") || strcaseeq(d->args[1], "aaaa")) {
            if (d->nargs != 4)
                FAIL("line %d: dynamic a needs a name and a port", d->line);
            if (arg_int(d, 3, &p->dyn_port, 1, 65535, err, errlen) < 0)
                return -1;
            p->dyn_kind = 1;
        } else if (strcaseeq(d->args[1], "srv")) {
            if (d->nargs != 3)
                FAIL("line %d: dynamic srv needs a name like _http._tcp.example.com", d->line);
            p->dyn_kind = 2;
        } else {
            FAIL("line %d: dynamic accepts 'a' or 'srv'", d->line);
        }
        free(p->dyn_name);
        p->dyn_name = xstrdup(d->args[2]);
        for (int i = 0; i < d->nkids; i++) {
            node_t *kk = d->kids[i];
            if (strcaseeq(kk->args[0], "refresh")) {
                if (want_args(kk, 1, 1, err, errlen) < 0 || arg_duration(kk, 1, &p->refresh, err, errlen) < 0)
                    return -1;
            } else {
                FAIL("line %d: unknown dynamic option '%s'", kk->line, kk->args[0]);
            }
        }
    } else if (strcaseeq(k, "discover")) {
        /* discover <name> [{ allow <cidr...>; settle <dur> }] : members come from the
         * self-registration registry (POST /register), not DNS. */
        if (d->nargs != 2)
            FAIL("line %d: discover needs a service name, e.g. 'discover orders'", d->line);
        if (p->dyn_kind)
            FAIL("line %d: a pool has one discovery source (dynamic or discover), not both", d->line);
        p->dyn_kind = DYN_REGISTRY;
        free(p->dyn_name);
        p->dyn_name = xstrdup(d->args[1]);
        for (int i = 0; i < d->nkids; i++) {
            node_t *kk = d->kids[i];
            if (strcaseeq(kk->args[0], "allow") || strcaseeq(kk->args[0], "allow_from")) {
                if (want_args(kk, 1, 256, err, errlen) < 0)
                    return -1;
                for (int a = 1; a < kk->nargs; a++) {
                    struct sockaddr_storage ss;
                    if (inet_pton(AF_INET, kk->args[a], &((struct sockaddr_in *)&ss)->sin_addr) != 1 &&
                        inet_pton(AF_INET6, kk->args[a], &((struct sockaddr_in6 *)&ss)->sin6_addr) != 1 &&
                        strchr(kk->args[a], '/') == NULL)
                        FAIL("line %d: discover allow needs an IP or CIDR, got '%s'", kk->line, kk->args[a]);
                    p->discover_allow = xrealloc(p->discover_allow, (size_t)(p->ndiscover_allow + 1) * sizeof(char *));
                    p->discover_allow[p->ndiscover_allow++] = xstrdup(kk->args[a]);
                }
            } else if (strcaseeq(kk->args[0], "settle")) {
                if (want_args(kk, 1, 1, err, errlen) < 0 || arg_duration(kk, 1, &p->settle, err, errlen) < 0)
                    return -1;
            } else {
                FAIL("line %d: unknown discover option '%s' (use allow, settle)", kk->line, kk->args[0]);
            }
        }
    } else if (strcaseeq(k, "refresh") || strcaseeq(k, "resolve_interval")) {
        if (want_args(d, 1, 1, err, errlen) < 0)
            return -1;
        if (strcaseeq(d->args[1], "off") || strcmp(d->args[1], "0") == 0)
            p->refresh = 0;
        else if (arg_duration(d, 1, &p->refresh, err, errlen) < 0)
            return -1;
    } else if (strcaseeq(k, "versions")) {
        /* transport http { versions h2 | h2c | 1.1 } */
        if (want_args(d, 1, -1, err, errlen) < 0)
            return -1;
        p->upstream_h2 = 0;
        for (int i = 1; i < d->nargs; i++) {
            if (strcaseeq(d->args[i], "h2") || strcmp(d->args[i], "2") == 0)
                p->upstream_h2 = 1;
            else if (strcaseeq(d->args[i], "h2c"))
                p->upstream_h2 = 2;
            else if (strcaseeq(d->args[i], "1.1") || strcaseeq(d->args[i], "h1"))
                ;
            else
                FAIL("line %d: versions accepts h2, h2c or 1.1", d->line);
        }
    } else if (strcaseeq(k, "tls_client_auth")) {
        /* tls_client_auth <cert.pem> <key.pem>: present a client certificate to upstreams */
        if (want_args(d, 2, 2, err, errlen) < 0)
            return -1;
        for (int a = 1; a <= 2; a++)
            if (access(d->args[a], R_OK) != 0)
                FAIL("line %d: tls_client_auth: cannot read '%s': %s", d->line, d->args[a], strerror(errno));
        free(p->tls_client_cert);
        free(p->tls_client_key);
        p->tls_client_cert = xstrdup(d->args[1]);
        p->tls_client_key = xstrdup(d->args[2]);
    } else if (strcaseeq(k, "tls_insecure_skip_verify")) {
        p->tls_insecure = 1;
    } else if (strcaseeq(k, "tls_server_name")) {
        if (want_args(d, 1, 1, err, errlen) < 0)
            return -1;
        free(p->tls_server_name);
        p->tls_server_name = xstrdup(d->args[1]);
    } else if (strcaseeq(k, "tls_trusted_ca_certs")) {
        if (want_args(d, 1, 1, err, errlen) < 0)
            return -1;
        free(p->tls_ca);
        p->tls_ca = xstrdup(d->args[1]);
    } else if (strcaseeq(k, "transport")) {
        /* Caddy compatibility: transport http { keepalive_idle_conns N; tls; ... } */
        for (int i = 0; i < d->nkids; i++) {
            int h = 0;
            node_t *c = d->kids[i];
            if (strcaseeq(c->args[0], "keepalive_idle_conns_per_host") || strcaseeq(c->args[0], "keepalive_idle_conns")) {
                if (want_args(c, 1, 1, err, errlen) < 0 || arg_int(c, 1, &p->keepalive_idle, 0, 100000, err, errlen) < 0)
                    return -1;
                continue;
            }
            if (parse_pool_directive(p, c, &h, err, errlen) < 0)
                return -1;
            if (!h)
                FAIL("line %d: unknown transport option '%s'", c->line, c->args[0]);
        }
    } else {
        *handled = 0;
    }
    return 0;
}

static int pool_finalize(pool_t *p, int line, char *err, size_t errlen)
{
    if (p->nups == 0 && !p->dyn_kind)
        FAIL("line %d: '%s' has no upstreams (use 'to host:port ...')", line, p->name);
    int pool_tls = p->tls_all;
    int any_tls = pool_tls, any_h2 = p->upstream_h2 != 0;
    for (int i = 0; i < p->nups; i++) {
        if (pool_tls)
            p->ups[i]->tls = 1;
        if (p->upstream_h2 == 1) {
            p->ups[i]->h2 = 1;
            p->ups[i]->tls = 1;
        } else if (p->upstream_h2 == 2) {
            p->ups[i]->h2 = 1;
        }
        if (p->ups[i]->tls)
            any_tls = 1;
        if (p->ups[i]->h2)
            any_h2 = 1;
    }
#ifndef LIMER_H2
    if (any_h2)
        FAIL("line %d: '%s': HTTP/2 upstreams need a build with nghttp2", line, p->name);
#endif
    (void)any_h2;
    if (any_tls && tls_init_pool_client(p, err, errlen) < 0)
        return -1;
    p->total_weight = 0;
    for (int i = 0; i < p->nups; i++)
        p->total_weight += p->ups[i]->weight;
    if (p->total_weight <= 0 && p->nups > 0)
        FAIL("line %d: '%s': all upstreams have weight 0", line, p->name);
    if (!p->dyn_kind && p->retries > p->nups - 1)
        p->retries = p->nups - 1;
    if (p->mirror) {
        if (p->mirror->nups == 0 && !p->mirror->dyn_kind)
            FAIL("line %d: mirror has no upstreams", line);
        if (pool_finalize(p->mirror, line, err, errlen) < 0)
            return -1;
    }
    return 0;
}

/* ---- upstreams that come and go at runtime (dynamic lookups, re-resolution) ---- */

upstream_t *upstream_new_resolved(pool_t *p, const char *host, const struct sockaddr *sa, socklen_t len, int port, int weight)
{
    upstream_t *u = xcalloc(1, sizeof *u);
    u->weight = weight > 0 ? weight : 1;
    u->host = xstrdup(host);
    u->port = port;
    u->tls = p->tls_all || p->upstream_h2 == 1;
    u->h2 = p->upstream_h2 != 0;
    memcpy(&u->addr, sa, len);
    u->addrlen = len;
    if (u->addr.ss_family == AF_INET)
        ((struct sockaddr_in *)&u->addr)->sin_port = htons((uint16_t)port);
    else if (u->addr.ss_family == AF_INET6)
        ((struct sockaddr_in6 *)&u->addr)->sin6_port = htons((uint16_t)port);
    u->resolved = 1;
    u->dynamic = 1;
    char ip[INET6_ADDRSTRLEN] = "?";
    if (sa->sa_family == AF_INET)
        inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, ip, sizeof ip);
    else if (sa->sa_family == AF_INET6)
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, ip, sizeof ip);
    char hp[300];
    if (sa->sa_family == AF_INET6)
        snprintf(hp, sizeof hp, "[%s]:%d", ip, port);
    else
        snprintf(hp, sizeof hp, "%s:%d", ip, port);
    u->hostport = xstrdup(hp);
    snprintf(u->sticky_id, sizeof u->sticky_id, "%016llx", (unsigned long long)hash64(hp, strlen(hp)));
    return u;
}

void upstream_free(upstream_t *u)
{
    if (!u)
        return;
    free(u->hostport);
    free(u->host);
    free(u);
}

void pool_recompute(pool_t *p)
{
    p->total_weight = 0;
    for (int i = 0; i < p->nups; i++)
        p->total_weight += p->ups[i]->weight;
    if (p->rr_index >= p->nups)
        p->rr_index = 0;
}

int pool_add_runtime(pool_t *p, upstream_t *u)
{
    if (p->nups >= 64)
        return -1;
    p->ups = xrealloc(p->ups, sizeof(upstream_t *) * (size_t)(p->nups + 1));
    p->ups[p->nups++] = u;
    pool_recompute(p);
    return 0;
}

void pool_retire_upstream(pool_t *p, int idx)
{
    upstream_t *u = p->ups[idx];
    memmove(p->ups + idx, p->ups + idx + 1, sizeof(upstream_t *) * (size_t)(p->nups - idx - 1));
    p->nups--;
    u->gone = 1;
    p->retired = xrealloc(p->retired, sizeof(upstream_t *) * (size_t)(p->nretired + 1));
    p->retired[p->nretired++] = u;
    pool_recompute(p);
}

void pool_reap_retired(pool_t *p)
{
    for (int i = 0; i < p->nretired;) {
        upstream_t *u = p->retired[i];
        if (u->active == 0 && u->nidle == 0 && !u->hc && !u->h2u) {
            upstream_free(u);
            memmove(p->retired + i, p->retired + i + 1, sizeof(upstream_t *) * (size_t)(p->nretired - i - 1));
            p->nretired--;
        } else {
            i++;
        }
    }
}

/* first-time lookup of dynamic pools while loading (blocking; failures only warn) */
static void config_resolve_dynamic(config_t *cfg)
{
    for (int i = 0; i < cfg->nservers; i++) {
        server_t *s = cfg->servers[i];
        for (int r = 0; r < s->nroutes; r++) {
            pool_t *p = s->routes[r]->pool;
            if (!p || !p->dyn_kind || p->dyn_kind == DYN_REGISTRY)
                continue;   /* a discover pool is filled from the registry, not DNS */
            resolve_job_t *job = xcalloc(1, sizeof *job);
            resolve_job_init(job, cfg, p->dyn_kind == 2 ? RESOLVE_SRV : RESOLVE_ADDR, p->dyn_name, p->dyn_port);
            resolve_sync(job);
            for (int k = 0; k < job->nres; k++) {
                resolve_result_t *rr = &job->res[k];
                upstream_t *u = upstream_new_resolved(p, rr->target, (struct sockaddr *)&rr->addr, rr->len, rr->port, rr->weight);
                int dup = 0;
                for (int m = 0; m < p->nups && !dup; m++)
                    dup = strcmp(p->ups[m]->hostport, u->hostport) == 0;
                if (dup || pool_add_runtime(p, u) < 0)
                    upstream_free(u);
            }
            if (job->nres == 0)
                LOGW("pool %s: dynamic %s %s: %s (pool starts empty)", p->name, p->dyn_kind == 2 ? "srv" : "a", p->dyn_name, job->err);
            else
                LOGI("pool %s: dynamic %s %s resolved to %d upstream(s)", p->name, p->dyn_kind == 2 ? "srv" : "a", p->dyn_name, job->nres);
            free(job);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Matchers and route-level directives                                 */
/* ------------------------------------------------------------------ */

static int parse_cache(cache_cfg_t **out, node_t *d, char *err, size_t errlen)
{
    cache_cfg_t *cc = xcalloc(1, sizeof *cc);
    cc->max_object = 1024 * 1024;   /* 1 MiB */
    cc->methods_head = 1;
    for (int i = 0; i < d->nkids; i++) {
        node_t *k = d->kids[i];
        const char *n = k->args[0];
        int rc = 0;
        if (strcaseeq(n, "ttl") || strcaseeq(n, "default_ttl")) {
            if ((rc = want_args(k, 1, 1, err, errlen)) == 0)
                rc = arg_duration(k, 1, &cc->ttl, err, errlen);
        } else if (strcaseeq(n, "stale") || strcaseeq(n, "stale_while_revalidate")) {
            if ((rc = want_args(k, 1, 1, err, errlen)) == 0)
                rc = arg_duration(k, 1, &cc->swr, err, errlen);
        } else if (strcaseeq(n, "max_object") || strcaseeq(n, "max_object_size")) {
            if ((rc = want_args(k, 1, 1, err, errlen)) == 0 && parse_size(k->args[1], &cc->max_object) < 0) {
                snprintf(err, errlen, "line %d: invalid size '%s'", k->line, k->args[1]);
                rc = -1;
            }
        } else if (strcaseeq(n, "methods")) {
            if ((rc = want_args(k, 1, -1, err, errlen)) == 0) {
                cc->methods_head = 0;
                for (int a = 1; a < k->nargs; a++) {
                    if (strcaseeq(k->args[a], "HEAD"))
                        cc->methods_head = 1;
                    else if (!strcaseeq(k->args[a], "GET")) {
                        snprintf(err, errlen, "line %d: cache only caches GET and HEAD", k->line);
                        rc = -1;
                    }
                }
            }
        } else {
            snprintf(err, errlen, "line %d: unknown cache option '%s'", k->line, n);
            rc = -1;
        }
        if (rc < 0) {
            free(cc);
            return -1;
        }
    }
    free(*out);
    *out = cc;
    return 0;
}

static void route_add_matcher(route_t *r, const matcher_t *m)
{
    r->m = xrealloc(r->m, sizeof(matcher_t) * (size_t)(r->nm + 1));
    r->m[r->nm++] = *m;
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
    if (ai < d->nargs && strcaseeq(d->args[ai], "split")) {
        /* match [not] split <percent> [<key-source> [name]] */
        ai++;
        if (ai >= d->nargs || !is_numeric(d->args[ai], &m.split_pct) || m.split_pct < 0 || m.split_pct > 100) {
            free(m.key.name);
            FAIL("line %d: 'match split' needs a percentage 0..100", d->line);
        }
        ai++;
        m.is_split = 1;
        m.split_key.src = KS_CLIENT_IP;
        if (ai < d->nargs) {
            int snamed;
            if (parse_keysrc(d->args[ai], &m.split_key.src, &snamed) < 0)
                FAIL("line %d: unknown split key source '%s'", d->line, d->args[ai]);
            ai++;
            if (snamed) {
                if (ai >= d->nargs)
                    FAIL("line %d: 'match split ... %s' needs a name", d->line, d->args[ai - 1]);
                m.split_key.name = xstrdup(d->args[ai++]);
            }
        }
        if (ai != d->nargs) {
            free(m.split_key.name);
            FAIL("line %d: 'match split' takes a percentage and an optional key source", d->line);
        }
        route_add_matcher(r, &m);
        return 0;
    }
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
        if (nvals) {
            free(m.key.name);
            FAIL("line %d: 'match ... %s' takes no values", d->line, d->args[ai - 1]);
        }
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

static void route_add_path_match(route_t *r, const char *pattern)
{
    matcher_t m;
    memset(&m, 0, sizeof m);
    m.key.src = KS_PATH;
    m.op = OP_EQ;
    m.vals = xcalloc(2, sizeof(char *));
    m.vals[0] = xstrdup(pattern);
    m.nvals = 1;
    r->m = xrealloc(r->m, sizeof(matcher_t) * (size_t)(r->nm + 1));
    r->m[r->nm++] = m;
}

static void route_add_rewrite(route_t *r, int kind, const char *a, const char *b)
{
    r->rw = xrealloc(r->rw, sizeof(rewrite_t) * (size_t)(r->nrw + 1));
    r->rw[r->nrw].kind = kind;
    r->rw[r->nrw].a = xstrdup(a);
    r->rw[r->nrw].b = b ? xstrdup(b) : NULL;
    r->nrw++;
}

/* "10r/s", "600r/m", "100r/h", or a plain number per second */
/* Does a listen address ("127.0.0.1:2019", "[::1]:2019", "localhost:2019")
 * only accept connections from this machine? ":2019" and "0.0.0.0:2019" do not. */
static int addr_is_loopback(const char *addr)
{
    char host[256];
    const char *colon = strrchr(addr, ':');
    size_t n = colon ? (size_t)(colon - addr) : strlen(addr);
    if (n >= sizeof host)
        return 0;
    memcpy(host, addr, n);
    host[n] = 0;
    char *h = host;
    if (*h == '[') {
        h++;
        char *e = strchr(h, ']');
        if (e)
            *e = 0;
    }
    return strncmp(h, "127.", 4) == 0 || strcaseeq(h, "localhost") || strcmp(h, "::1") == 0;
}

static int parse_rate(const char *s, double *out)
{
    char *end;
    double v = strtod(s, &end);
    if (end == s || v <= 0)
        return -1;
    if (*end == 0) {
        *out = v;
        return 0;
    }
    if (strcmp(end, "r/s") == 0 || strcmp(end, "/s") == 0)
        *out = v;
    else if (strcmp(end, "r/m") == 0 || strcmp(end, "/m") == 0)
        *out = v / 60.0;
    else if (strcmp(end, "r/h") == 0 || strcmp(end, "/h") == 0)
        *out = v / 3600.0;
    else
        return -1;
    return 0;
}

/* rate_limit [zone] [rate] { key <tmpl>; rate <r>; burst <n>; status <code>; max_keys <n> } */
static int parse_rate_limit(rate_limit_cfg_t **out, node_t *d, char *err, size_t errlen)
{
    rate_limit_cfg_t *r = xcalloc(1, sizeof *r);
    r->status = 429;
    r->max_keys = 100000;
    int ai = 1;
    if (ai < d->nargs && parse_rate(d->args[ai], &r->rate) < 0) {
        r->name = xstrdup(d->args[ai++]);
        if (ai < d->nargs && parse_rate(d->args[ai], &r->rate) == 0)
            ai++;
    } else if (ai < d->nargs) {
        ai++;
    }
    if (ai < d->nargs) {
        rl_cfg_free(r);
        FAIL("line %d: rate_limit accepts [zone] [rate] followed by an options block", d->line);
    }
    for (int i = 0; i < d->nkids; i++) {
        node_t *k = d->kids[i];
        const char *n = k->args[0];
        int rc = 0;
        if (strcaseeq(n, "key")) {
            if ((rc = want_args(k, 1, 1, err, errlen)) == 0) {
                free(r->key);
                r->key = xstrdup(k->args[1]);
            }
        } else if (strcaseeq(n, "rate") || strcaseeq(n, "events")) {
            if ((rc = want_args(k, 1, 1, err, errlen)) == 0 && parse_rate(k->args[1], &r->rate) < 0) {
                snprintf(err, errlen, "line %d: invalid rate '%s' (use e.g. 10r/s, 600r/m)", k->line, k->args[1]);
                rc = -1;
            }
        } else if (strcaseeq(n, "burst")) {
            if ((rc = want_args(k, 1, 1, err, errlen)) == 0) {
                r->burst = atof(k->args[1]);
                if (r->burst <= 0) {
                    snprintf(err, errlen, "line %d: burst must be positive", k->line);
                    rc = -1;
                }
            }
        } else if (strcaseeq(n, "status")) {
            if ((rc = want_args(k, 1, 1, err, errlen)) == 0)
                rc = arg_int(k, 1, &r->status, 400, 599, err, errlen);
        } else if (strcaseeq(n, "max_keys")) {
            if ((rc = want_args(k, 1, 1, err, errlen)) == 0)
                rc = arg_int(k, 1, &r->max_keys, 1, 100000000, err, errlen);
        } else {
            snprintf(err, errlen, "line %d: unknown rate_limit option '%s'", k->line, n);
            rc = -1;
        }
        if (rc < 0) {
            rl_cfg_free(r);
            return -1;
        }
    }
    if (r->rate <= 0) {
        rl_cfg_free(r);
        FAIL("line %d: rate_limit needs a rate (e.g. 'rate 10r/s')", d->line);
    }
    if (!r->key)
        r->key = xstrdup("{remote_ip}");
    if (!r->name)
        r->name = xstrdup("default");
    if (r->burst <= 0)
        r->burst = r->rate < 1 ? 1 : r->rate;
    r->rl = ratelimit_new(r->rate, r->burst, r->max_keys);
    rl_cfg_free(*out);
    *out = r;
    return 0;
}

static int parse_basic_auth(basic_auth_t **out, node_t *d, char *err, size_t errlen)
{
    /* basic_auth [bcrypt] [realm] { user hash ... } */
    basic_auth_t *a = xcalloc(1, sizeof *a);
    int ai = 1;
    if (ai < d->nargs && strcaseeq(d->args[ai], "bcrypt"))
        ai++;
    if (ai < d->nargs)
        a->realm = xstrdup(d->args[ai++]);
    if (ai < d->nargs) {
        auth_free(a);
        FAIL("line %d: basic_auth accepts [bcrypt] [realm] followed by a block of 'user hash' lines", d->line);
    }
    for (int i = 0; i < d->nkids; i++) {
        node_t *k = d->kids[i];
        if (k->nargs != 2) {
            auth_free(a);
            FAIL("line %d: basic_auth entries are '<user> <hash>'", k->line);
        }
        if (!str_has_prefix(k->args[1], "$2") && !str_has_prefix(k->args[1], "$6$") && !str_has_prefix(k->args[1], "$5$")) {
            auth_free(a);
            FAIL("line %d: basic_auth: password for '%s' must be a bcrypt hash (e.g. from `htpasswd -nbB user pass`)", k->line, k->args[0]);
        }
        a->users = xrealloc(a->users, sizeof(auth_user_t) * (size_t)(a->nusers + 1));
        a->users[a->nusers].name = xstrdup(k->args[0]);
        a->users[a->nusers].hash = xstrdup(k->args[1]);
        a->nusers++;
    }
    if (a->nusers == 0) {
        auth_free(a);
        FAIL("line %d: basic_auth has no users", d->line);
    }
    if (!a->realm)
        a->realm = xstrdup("restricted");
    auth_free(*out);
    *out = a;
    return 0;
}

static int parse_respond(route_t *r, node_t *d, char *err, size_t errlen)
{
    /* respond [status] | [body] | [body status] | [status body] */
    r->kind = ROUTE_RESPOND;
    r->resp_status = 200;
    int ai = 1;
    int have_status = 0;
    if (ai < d->nargs && is_numeric(d->args[ai], NULL)) {
        if (arg_int(d, ai, &r->resp_status, 100, 599, err, errlen) < 0)
            return -1;
        have_status = 1;
        ai++;
    }
    if (ai < d->nargs) {
        free(r->resp_body);
        r->resp_body = xstrdup(d->args[ai++]);
    }
    if (ai < d->nargs && !have_status && is_numeric(d->args[ai], NULL)) {
        if (arg_int(d, ai, &r->resp_status, 100, 599, err, errlen) < 0)
            return -1;
        ai++;
    }
    for (int i = 0; i < d->nkids; i++) {
        node_t *k = d->kids[i];
        if (strcaseeq(k->args[0], "body") && k->nargs == 2) {
            free(r->resp_body);
            r->resp_body = xstrdup(k->args[1]);
        } else if (strcaseeq(k->args[0], "close")) {
            ; /* accepted for compatibility */
        } else {
            FAIL("line %d: unknown respond option '%s'", k->line, k->args[0]);
        }
    }
    if (ai < d->nargs)
        FAIL("line %d: 'respond' accepts [status] [body] or [body] [status]", d->line);
    return 0;
}

static int parse_redirect(route_t *r, node_t *d, char *err, size_t errlen)
{
    /* redir <location> [code|permanent|temporary] */
    if (want_args(d, 1, 2, err, errlen) < 0)
        return -1;
    r->kind = ROUTE_REDIRECT;
    r->resp_status = 302;
    free(r->resp_body);
    r->resp_body = xstrdup(d->args[1]);
    if (d->nargs > 2) {
        if (strcaseeq(d->args[2], "permanent"))
            r->resp_status = 301;
        else if (strcaseeq(d->args[2], "temporary"))
            r->resp_status = 302;
        else if (arg_int(d, 2, &r->resp_status, 300, 399, err, errlen) < 0)
            return -1;
    }
    return 0;
}

static int parse_error(route_t *r, node_t *d, char *err, size_t errlen)
{
    /* error [message] <status> | error <status> [message] */
    r->kind = ROUTE_ERROR;
    r->resp_status = 500;
    int ai = 1;
    int have = 0;
    if (ai < d->nargs && is_numeric(d->args[ai], NULL)) {
        if (arg_int(d, ai, &r->resp_status, 400, 599, err, errlen) < 0)
            return -1;
        have = 1;
        ai++;
    }
    if (ai < d->nargs && (!is_numeric(d->args[ai], NULL) || have)) {
        free(r->resp_body);
        r->resp_body = xstrdup(d->args[ai++]);
    }
    if (ai < d->nargs && !have && is_numeric(d->args[ai], NULL)) {
        if (arg_int(d, ai, &r->resp_status, 400, 599, err, errlen) < 0)
            return -1;
        have = 1;
        ai++;
    }
    if (!have)
        FAIL("line %d: 'error' needs a status code (400-599)", d->line);
    if (ai < d->nargs)
        FAIL("line %d: 'error' accepts [message] <status>", d->line);
    return 0;
}

static file_server_t *files_new(void)
{
    file_server_t *f = xcalloc(1, sizeof *f);
    f->index = xcalloc(2, sizeof(char *));
    f->index[0] = xstrdup("index.html");
    f->nindex = 1;
    f->hide_dotfiles = 1;
    return f;
}

static int parse_file_server(file_server_t *f, node_t *d, char *err, size_t errlen)
{
    /* file_server [browse] { root DIR; index a b; browse; hide .git; } */
    for (int i = 1; i < d->nargs; i++) {
        if (strcaseeq(d->args[i], "browse"))
            f->browse = 1;
        else
            FAIL("line %d: file_server accepts only 'browse' inline", d->line);
    }
    for (int i = 0; i < d->nkids; i++) {
        node_t *k = d->kids[i];
        const char *n = k->args[0];
        if (strcaseeq(n, "root")) {
            if (want_args(k, 1, 1, err, errlen) < 0)
                return -1;
            free(f->root);
            f->root = xstrdup(k->args[1]);
        } else if (strcaseeq(n, "index")) {
            if (want_args(k, 1, -1, err, errlen) < 0)
                return -1;
            for (int j = 0; j < f->nindex; j++)
                free(f->index[j]);
            free(f->index);
            f->index = xcalloc((size_t)k->nargs, sizeof(char *));
            f->nindex = 0;
            for (int j = 1; j < k->nargs; j++)
                f->index[f->nindex++] = xstrdup(k->args[j]);
        } else if (strcaseeq(n, "browse")) {
            f->browse = 1;
        } else if (strcaseeq(n, "hide")) {
            ; /* dotfiles are always hidden */
        } else {
            FAIL("line %d: unknown file_server option '%s'", k->line, n);
        }
    }
    return 0;
}

/* Route-level directives shared by route/handle blocks. Returns 1 handled, 0 not, -1 error. */
static int parse_route_directive(route_t *r, pool_t *p, node_t *c, char **root_hint, char *err, size_t errlen)
{
    const char *k = c->args[0];
    if (strcaseeq(k, "match")) {
        return parse_match(r, c, err, errlen) < 0 ? -1 : 1;
    }
    if (strcaseeq(k, "respond")) {
        if (r->kind >= 0 && r->kind != ROUTE_RESPOND)
            FAIL("line %d: route has more than one handler", c->line);
        return parse_respond(r, c, err, errlen) < 0 ? -1 : 1;
    }
    if (strcaseeq(k, "redir") || strcaseeq(k, "redirect")) {
        if (r->kind >= 0)
            FAIL("line %d: route has more than one handler", c->line);
        return parse_redirect(r, c, err, errlen) < 0 ? -1 : 1;
    }
    if (strcaseeq(k, "error")) {
        if (r->kind >= 0)
            FAIL("line %d: route has more than one handler", c->line);
        return parse_error(r, c, err, errlen) < 0 ? -1 : 1;
    }
    if (strcaseeq(k, "abort")) {
        if (r->kind >= 0)
            FAIL("line %d: route has more than one handler", c->line);
        r->kind = ROUTE_ABORT;
        return 1;
    }
    if (strcaseeq(k, "file_server")) {
        if (r->kind >= 0)
            FAIL("line %d: route has more than one handler", c->line);
        r->kind = ROUTE_FILES;
        if (!r->files)
            r->files = files_new();
        return parse_file_server(r->files, c, err, errlen) < 0 ? -1 : 1;
    }
    if (strcaseeq(k, "root")) {
        if (want_args(c, 1, 1, err, errlen) < 0)
            return -1;
        free(*root_hint);
        *root_hint = xstrdup(c->args[1]);
        return 1;
    }
    if (strcaseeq(k, "try_files")) {
        if (want_args(c, 1, -1, err, errlen) < 0)
            return -1;
        if (!r->files)
            r->files = files_new();
        for (int i = 1; i < c->nargs; i++) {
            r->files->try_files = xrealloc(r->files->try_files, sizeof(char *) * (size_t)(r->files->ntry + 1));
            r->files->try_files[r->files->ntry++] = xstrdup(c->args[i]);
        }
        return 1;
    }
    if (strcaseeq(k, "reverse_proxy")) {
        if (pool_add_upstream_list(p, c, 1, err, errlen) < 0)
            return -1;
        for (int j = 0; j < c->nkids; j++) {
            int h2 = 0;
            if (parse_pool_directive(p, c->kids[j], &h2, err, errlen) < 0)
                return -1;
            if (!h2)
                FAIL("line %d: unknown reverse_proxy option '%s'", c->kids[j]->line, c->kids[j]->args[0]);
        }
        if (r->kind >= 0 && r->kind != ROUTE_PROXY)
            FAIL("line %d: route has more than one handler", c->line);
        r->kind = ROUTE_PROXY;
        return 1;
    }
    if (strcaseeq(k, "rewrite")) {
        if (want_args(c, 1, 1, err, errlen) < 0)
            return -1;
        route_add_rewrite(r, RW_URI, c->args[1], NULL);
        return 1;
    }
    if (strcaseeq(k, "uri")) {
        if (want_args(c, 2, 3, err, errlen) < 0)
            return -1;
        const char *what = c->args[1];
        if (strcaseeq(what, "strip_prefix") && c->nargs == 3)
            route_add_rewrite(r, RW_STRIP_PREFIX, c->args[2], NULL);
        else if (strcaseeq(what, "strip_suffix") && c->nargs == 3)
            route_add_rewrite(r, RW_STRIP_SUFFIX, c->args[2], NULL);
        else if (strcaseeq(what, "replace") && c->nargs == 4)
            route_add_rewrite(r, RW_REPLACE, c->args[2], c->args[3]);
        else
            FAIL("line %d: uri accepts 'strip_prefix <p>', 'strip_suffix <s>' or 'replace <find> <replacement>'", c->line);
        return 1;
    }
    if (strcaseeq(k, "basic_auth") || strcaseeq(k, "basicauth")) {
        return parse_basic_auth(&r->auth, c, err, errlen) < 0 ? -1 : 1;
    }
    if (strcaseeq(k, "rate_limit")) {
        return parse_rate_limit(&r->rl, c, err, errlen) < 0 ? -1 : 1;
    }
    if (strcaseeq(k, "cache")) {
        return parse_cache(&r->cache, c, err, errlen) < 0 ? -1 : 1;
    }
    if (strcaseeq(k, "header") || strcaseeq(k, "header_down")) {
        return add_hdr_ops(&p->hdr_down, &p->n_hdr_down, c, err, errlen) < 0 ? -1 : 1;
    }
    int handled = 0;
    if (parse_pool_directive(p, c, &handled, err, errlen) < 0)
        return -1;
    if (handled) {
        if (strcaseeq(k, "to") || strcaseeq(k, "upstream") || strcaseeq(k, "upstreams")) {
            if (r->kind >= 0 && r->kind != ROUTE_PROXY)
                FAIL("line %d: route has more than one handler", c->line);
            r->kind = ROUTE_PROXY;
        }
        return 1;
    }
    return 0;
}

/* Finish a route after its directives were parsed. Takes ownership of p and root_hint. */
static int route_finish(server_t *s, route_t *r, pool_t *p, char *root_hint, const char *server_root, int line, char *err, size_t errlen)
{
    if (r->kind < 0) {
        if (r->files && r->files->ntry) {
            snprintf(err, errlen, "line %d: route '%s' uses try_files without file_server", line, r->name);
            goto fail;
        }
        snprintf(err, errlen, "line %d: route '%s' has no handler (reverse_proxy/to, respond, redir, error, abort, file_server)", line, r->name);
        goto fail;
    }
    if (r->kind == ROUTE_PROXY) {
        if (pool_finalize(p, line, err, errlen) < 0)
            goto fail;
        r->pool = p;
        p = NULL;
    } else {
        r->hdr_down = p->hdr_down;
        r->n_hdr_down = p->n_hdr_down;
        p->hdr_down = NULL;
        p->n_hdr_down = 0;
        if (p->nups) {
            snprintf(err, errlen, "line %d: route '%s' has upstreams but a non-proxy handler", line, r->name);
            goto fail;
        }
        pool_free(p);
        p = NULL;
    }
    if (r->kind == ROUTE_FILES) {
        if (!r->files->root) {
            const char *root = root_hint ? root_hint : server_root;
            if (!root) {
                snprintf(err, errlen, "line %d: file_server needs a 'root' directory", line);
                goto fail;
            }
            r->files->root = xstrdup(root);
        }
        if (access(r->files->root, R_OK) != 0) {
            snprintf(err, errlen, "line %d: file_server root '%s': %s", line, r->files->root, strerror(errno));
            goto fail;
        }
    }
    free(root_hint);
    route_compute_needs_body(r);
    s->routes = xrealloc(s->routes, sizeof(route_t *) * (size_t)(s->nroutes + 1));
    s->routes[s->nroutes++] = r;
    return 0;
fail:
    pool_free(p);
    free(root_hint);
    route_free(r);
    return -1;
}

static int parse_route(server_t *s, node_t *d, const char *server_root, char *err, size_t errlen)
{
    /* route [name|/path-pattern] { ... }  |  handle [/path-pattern] { ... }  |  handle_path /prefix/ * { ... } */
    route_t *r = xcalloc(1, sizeof *r);
    char name[64];
    const char *kw = d->args[0];
    int is_handle_path = strcaseeq(kw, "handle_path");
    if (d->nargs > 2) {
        free(r);
        FAIL("line %d: '%s' takes at most one argument", d->line, kw);
    }
    snprintf(name, sizeof name, "%s%d", is_handle_path ? "handle_path" : strcaseeq(kw, "handle") ? "handle" : "route", s->nroutes + 1);
    if (d->nargs == 2) {
        const char *a = d->args[1];
        if (a[0] == '/' || a[0] == '*') {
            route_add_path_match(r, a);
            if (is_handle_path) {
                /* strip the literal prefix (pattern without its trailing wildcard) */
                char prefix[1024];
                snprintf(prefix, sizeof prefix, "%s", a);
                size_t n = strlen(prefix);
                if (n && prefix[n - 1] == '*')
                    prefix[--n] = 0;
                if (n > 1 && prefix[n - 1] == '/')
                    prefix[--n] = 0;
                if (n)
                    route_add_rewrite(r, RW_STRIP_PREFIX, prefix, NULL);
            }
        } else if (is_handle_path) {
            free(r);
            FAIL("line %d: handle_path needs a path pattern like /api/*", d->line);
        } else {
            snprintf(name, sizeof name, "%s", a);
        }
    } else if (is_handle_path) {
        free(r);
        FAIL("line %d: handle_path needs a path pattern like /api/*", d->line);
    }
    r->name = xstrdup(name);
    r->kind = -1;
    pool_t *p = pool_new(name);
    char *root_hint = NULL;
    for (int i = 0; i < d->nkids; i++) {
        node_t *c = d->kids[i];
        int rc = parse_route_directive(r, p, c, &root_hint, err, errlen);
        if (rc < 0)
            goto fail;
        if (rc == 0) {
            snprintf(err, errlen, "line %d: unknown directive '%s' in %s", c->line, c->args[0], kw);
            goto fail;
        }
    }
    return route_finish(s, r, p, root_hint, server_root, d->line, err, errlen);
fail:
    pool_free(p);
    free(root_hint);
    route_free(r);
    return -1;
}

/* top-level `reverse_proxy [upstreams...] [{ options }]` = catch-all proxy route */
static int parse_reverse_proxy(server_t *s, node_t *d, char *err, size_t errlen)
{
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
    route_compute_needs_body(r);
    s->routes = xrealloc(s->routes, sizeof(route_t *) * (size_t)(s->nroutes + 1));
    s->routes[s->nroutes++] = r;
    return 0;
fail:
    pool_free(p);
    route_free(r);
    return -1;
}

/* a standalone handler directive at server level becomes a catch-all route */
static int parse_simple_route(server_t *s, node_t *d, const char *server_root, char *err, size_t errlen)
{
    route_t *r = xcalloc(1, sizeof *r);
    char name[64];
    snprintf(name, sizeof name, "%s%d", d->args[0], s->nroutes + 1);
    r->name = xstrdup(name);
    r->kind = -1;
    pool_t *p = pool_new(name);
    char *root_hint = NULL;
    int rc = parse_route_directive(r, p, d, &root_hint, err, errlen);
    if (rc <= 0) {
        if (rc == 0)
            snprintf(err, errlen, "line %d: unknown directive '%s'", d->line, d->args[0]);
        pool_free(p);
        free(root_hint);
        route_free(r);
        return -1;
    }
    return route_finish(s, r, p, root_hint, server_root, d->line, err, errlen);
}

/* ------------------------------------------------------------------ */
/* Site addresses                                                      */
/* ------------------------------------------------------------------ */

typedef struct site_addr {
    int scheme;     /* 0 none, 1 http, 2 https */
    char host[256]; /* "" = any */
    int port;       /* 0 = unspecified */
} site_addr_t;

static int parse_site_address(const char *text, site_addr_t *out, char *err, size_t errlen, int line)
{
    memset(out, 0, sizeof *out);
    const char *s = text;
    if (str_has_prefix(s, "https://")) {
        out->scheme = 2;
        s += 8;
    } else if (str_has_prefix(s, "http://")) {
        out->scheme = 1;
        s += 7;
    }
    size_t n = strlen(s);
    while (n && s[n - 1] == '/')
        n--;
    char tmp[256];
    if (n >= sizeof tmp || n == 0)
        FAIL("line %d: invalid site address '%s'", line, text);
    memcpy(tmp, s, n);
    tmp[n] = 0;
    char *host = tmp;
    char *portstr = NULL;
    if (tmp[0] == '[') {
        char *rb = strchr(tmp, ']');
        if (!rb)
            FAIL("line %d: invalid site address '%s'", line, text);
        *rb = 0;
        host = tmp + 1;
        if (rb[1] == ':')
            portstr = rb + 2;
        else if (rb[1])
            FAIL("line %d: invalid site address '%s'", line, text);
    } else {
        char *c = strrchr(tmp, ':');
        if (c && strchr(tmp, ':') == c) {
            *c = 0;
            portstr = c + 1;
        } else if (c) {
            FAIL("line %d: invalid site address '%s' (wrap IPv6 addresses in [])", line, text);
        }
    }
    if (portstr) {
        char *end;
        long v = strtol(portstr, &end, 10);
        if (end == portstr || *end || v < 1 || v > 65535)
            FAIL("line %d: invalid port in site address '%s'", line, text);
        out->port = (int)v;
    }
    if (strlen(host) >= sizeof out->host)
        FAIL("line %d: site address too long", line);
    for (const char *p = host; *p; p++)
        if (!(isalnum((unsigned char)*p) || strchr("-.*_:", *p)))
            FAIL("line %d: invalid hostname in site address '%s'", line, text);
    snprintf(out->host, sizeof out->host, "%s", host);
    if (!out->host[0] && !out->port)
        FAIL("line %d: site address '%s' needs a host or a port", line, text);
    return 0;
}

static void server_add_bind(server_t *s, const char *bind)
{
    for (int i = 0; i < s->naddr; i++)
        if (strcmp(s->addrs[i], bind) == 0)
            return;
    s->addrs = xrealloc(s->addrs, sizeof(char *) * (size_t)(s->naddr + 1));
    s->addrs[s->naddr++] = xstrdup(bind);
}

static void server_add_host(server_t *s, const char *host)
{
    for (int i = 0; i < s->nhosts; i++)
        if (strcasecmp(s->hosts[i], host) == 0)
            return;
    s->hosts = xrealloc(s->hosts, sizeof(char *) * (size_t)(s->nhosts + 1));
    s->hosts[s->nhosts++] = xstrdup(host);
}

static server_t *server_new(void)
{
    server_t *s = xcalloc(1, sizeof *s);
    s->max_body = 8 * 1024 * 1024;
    s->read_timeout = 30;
    s->idle_timeout = 120;
    s->log_fd = -1;
    s->encode_min = 512;
    return s;
}

static int parse_log(server_t *s, node_t *d, char *err, size_t errlen)
{
    /* log [off] { output stdout|stderr|<file>; format json|common } */
    s->access_log = 1;
    if (s->log_fd < 0)
        s->log_fd = STDOUT_FILENO;
    if (d->nargs > 1) {
        if (strcaseeq(d->args[1], "off")) {
            s->access_log = 0;
            return 0;
        }
        if (arg_bool(d, 1, &s->access_log, err, errlen) < 0)
            return -1;
    }
    for (int i = 0; i < d->nkids; i++) {
        node_t *k = d->kids[i];
        if (strcaseeq(k->args[0], "output")) {
            if (want_args(k, 1, 2, err, errlen) < 0)
                return -1;
            const char *spec = k->args[1];
            char fspec[1024];
            if (strcaseeq(spec, "file")) {
                if (k->nargs < 3)
                    FAIL("line %d: 'output file' needs a path", k->line);
                snprintf(fspec, sizeof fspec, "%s", k->args[2]);
                spec = fspec;
            }
            if (s->log_fd > 2)
                close(s->log_fd);
            s->log_fd = log_open_target(spec, err, errlen);
            if (s->log_fd < 0 && !(strcaseeq(spec, "off") || strcaseeq(spec, "discard") || strcaseeq(spec, "none")))
                return -1;
        } else if (strcaseeq(k->args[0], "format")) {
            if (want_args(k, 1, 1, err, errlen) < 0)
                return -1;
            if (strcaseeq(k->args[1], "json"))
                s->log_json = 1;
            else if (strcaseeq(k->args[1], "common") || strcaseeq(k->args[1], "console") || strcaseeq(k->args[1], "text"))
                s->log_json = 0;
            else
                FAIL("line %d: log format must be json or common", k->line);
        } else {
            FAIL("line %d: unknown log option '%s'", k->line, k->args[0]);
        }
    }
    return 0;
}

/* tls ... { client_auth { mode <m>; trusted_ca_cert_file <pem> ... } } */
static int parse_client_auth(server_t *s, node_t *d, char *err, size_t errlen)
{
    if (d->nargs > 1)
        FAIL("line %d: client_auth takes a block, not arguments", d->line);
    s->client_auth_mode = CA_REQUIRE_AND_VERIFY;
    for (int i = 0; i < d->nkids; i++) {
        node_t *k = d->kids[i];
        const char *n = k->args[0];
        if (strcaseeq(n, "mode")) {
            if (want_args(k, 1, 1, err, errlen) < 0)
                return -1;
            const char *m = k->args[1];
            if (strcaseeq(m, "request"))
                s->client_auth_mode = CA_REQUEST;
            else if (strcaseeq(m, "require"))
                s->client_auth_mode = CA_REQUIRE;
            else if (strcaseeq(m, "verify_if_given"))
                s->client_auth_mode = CA_VERIFY_IF_GIVEN;
            else if (strcaseeq(m, "require_and_verify"))
                s->client_auth_mode = CA_REQUIRE_AND_VERIFY;
            else
                FAIL("line %d: client_auth mode accepts request, require, verify_if_given or require_and_verify", k->line);
        } else if (strcaseeq(n, "trusted_ca_cert_file") || strcaseeq(n, "trusted_ca_cert")) {
            if (want_args(k, 1, -1, err, errlen) < 0)
                return -1;
            for (int a = 1; a < k->nargs; a++) {
                if (access(k->args[a], R_OK) != 0)
                    FAIL("line %d: client_auth: cannot read '%s': %s", k->line, k->args[a], strerror(errno));
                s->client_ca = xrealloc(s->client_ca, sizeof(char *) * (size_t)(s->nclient_ca + 1));
                s->client_ca[s->nclient_ca++] = xstrdup(k->args[a]);
            }
        } else {
            FAIL("line %d: unknown client_auth option '%s'", k->line, n);
        }
    }
    if ((s->client_auth_mode == CA_VERIFY_IF_GIVEN || s->client_auth_mode == CA_REQUIRE_AND_VERIFY) && s->nclient_ca == 0)
        FAIL("line %d: client_auth mode %s needs trusted_ca_cert_file", d->line,
             s->client_auth_mode == CA_VERIFY_IF_GIVEN ? "verify_if_given" : "require_and_verify");
    return 0;
}

static int parse_tls(server_t *s, node_t *d, char *err, size_t errlen)
{
    /* tls internal | tls <cert> <key> | tls <email> | tls  -- each with an optional { client_auth { } } block */
    if (d->nargs == 2 && strcaseeq(d->args[1], "internal")) {
        s->tls_mode = TLS_INTERNAL;
    } else if (d->nargs == 3) {
        free(s->tls_cert);
        free(s->tls_key);
        s->tls_cert = xstrdup(d->args[1]);
        s->tls_key = xstrdup(d->args[2]);
        s->tls_mode = TLS_FILES;
    } else if (d->nargs == 2 && strchr(d->args[1], '@')) {
        s->tls_mode = TLS_AUTO;
        free(s->tls_cert);
        s->tls_cert = xstrdup(d->args[1]); /* account email for ACME */
    } else if (d->nargs == 1 && d->nkids) {
        s->tls_mode = TLS_AUTO;
    } else {
        FAIL("line %d: tls accepts 'internal', '<cert.pem> <key.pem>' or an email for automatic certificates", d->line);
    }
    for (int i = 0; i < d->nkids; i++) {
        node_t *k = d->kids[i];
        if (strcaseeq(k->args[0], "client_auth")) {
            if (parse_client_auth(s, k, err, errlen) < 0)
                return -1;
        } else {
            FAIL("line %d: unknown tls option '%s'", k->line, k->args[0]);
        }
    }
    return 0;
}

static int parse_server(config_t *cfg, node_t *d, char *err, size_t errlen)
{
    server_t *s = server_new();
    int tls_implied = 0, plain_implied = 0;
    for (int i = 0; i < d->nargs; i++) {
        char *a = xstrdup(d->args[i]);
        size_t l = strlen(a);
        while (l && a[l - 1] == ',')
            a[--l] = 0;
        if (!l) {
            free(a);
            continue;
        }
        site_addr_t sa;
        if (parse_site_address(a, &sa, err, errlen, d->line) < 0) {
            free(a);
            server_free(s);
            return -1;
        }
        free(a);
        int is_ip = sa.host[0] && is_ip_literal(sa.host);
        int tls;
        if (sa.scheme == 2)
            tls = 1;
        else if (sa.scheme == 1)
            tls = 0;
        else if (sa.host[0] && !is_ip)
            tls = sa.port != cfg->http_port;
        else
            tls = 0;
        int port = sa.port ? sa.port : (tls ? cfg->https_port : cfg->http_port);
        if (!sa.port && !sa.host[0]) {
            server_free(s);
            FAIL("line %d: site address needs a port", d->line);
        }
        if (tls)
            tls_implied = 1;
        else
            plain_implied = 1;
        char bind[320];
        if (is_ip)
            snprintf(bind, sizeof bind, strchr(sa.host, ':') ? "[%s]:%d" : "%s:%d", sa.host, port);
        else
            snprintf(bind, sizeof bind, ":%d", port);
        server_add_bind(s, bind);
        if (sa.host[0] && !is_ip)
            server_add_host(s, sa.host);
        if (!s->port)
            s->port = port;
    }
    if (s->naddr == 0) {
        server_free(s);
        FAIL("line %d: server block has no listen address", d->line);
    }
    if (tls_implied && plain_implied) {
        server_free(s);
        FAIL("line %d: a site block cannot mix http and https addresses", d->line);
    }
    if (tls_implied)
        s->tls_mode = TLS_AUTO;

    char *server_root = NULL;
    for (int i = 0; i < d->nkids; i++) {
        node_t *c = d->kids[i];
        const char *k = c->args[0];
        int rc = 0;
        if (strcaseeq(k, "route") || strcaseeq(k, "handle") || strcaseeq(k, "handle_path")) {
            rc = parse_route(s, c, server_root, err, errlen);
        } else if (strcaseeq(k, "reverse_proxy")) {
            rc = parse_reverse_proxy(s, c, err, errlen);
        } else if (strcaseeq(k, "respond") || strcaseeq(k, "redir") || strcaseeq(k, "redirect") ||
                   strcaseeq(k, "error") || strcaseeq(k, "abort") || strcaseeq(k, "file_server")) {
            rc = parse_simple_route(s, c, server_root, err, errlen);
        } else if (strcaseeq(k, "root")) {
            if ((rc = want_args(c, 1, 1, err, errlen)) == 0) {
                free(server_root);
                server_root = xstrdup(c->args[1]);
            }
        } else if (strcaseeq(k, "max_body") || strcaseeq(k, "max_body_size") || strcaseeq(k, "request_body")) {
            if (c->nkids && c->nargs == 1) {
                /* request_body { max_size 10MB } */
                for (int j = 0; j < c->nkids && rc == 0; j++) {
                    node_t *kk = c->kids[j];
                    if (strcaseeq(kk->args[0], "max_size") && kk->nargs == 2) {
                        if (parse_size(kk->args[1], &s->max_body) < 0) {
                            snprintf(err, errlen, "line %d: invalid size '%s'", kk->line, kk->args[1]);
                            rc = -1;
                        }
                    } else if (strcaseeq(kk->args[0], "mode") && kk->nargs == 2) {
                        /* mode stream (default: stream unless something reads the body) | buffer */
                        if (strcaseeq(kk->args[1], "stream") || strcaseeq(kk->args[1], "auto"))
                            s->body_mode = 0;
                        else if (strcaseeq(kk->args[1], "buffer"))
                            s->body_mode = 1;
                        else {
                            snprintf(err, errlen, "line %d: request_body mode accepts stream or buffer", kk->line);
                            rc = -1;
                        }
                    } else {
                        snprintf(err, errlen, "line %d: unknown request_body option '%s'", kk->line, kk->args[0]);
                        rc = -1;
                    }
                }
            } else if ((rc = want_args(c, 1, 1, err, errlen)) == 0 && parse_size(c->args[1], &s->max_body) < 0) {
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
            rc = parse_log(s, c, err, errlen);
        } else if (strcaseeq(k, "tls")) {
            rc = parse_tls(s, c, err, errlen);
        } else if (strcaseeq(k, "header")) {
            rc = add_hdr_ops(&s->hdr_down, &s->n_hdr_down, c, err, errlen);
        } else if (strcaseeq(k, "request_header") || strcaseeq(k, "header_up")) {
            rc = add_hdr_ops(&s->hdr_up, &s->n_hdr_up, c, err, errlen);
        } else if (strcaseeq(k, "basic_auth") || strcaseeq(k, "basicauth")) {
            rc = parse_basic_auth(&s->auth, c, err, errlen);
        } else if (strcaseeq(k, "rate_limit")) {
            rc = parse_rate_limit(&s->rl, c, err, errlen);
        } else if (strcaseeq(k, "cache")) {
            rc = parse_cache(&s->cache, c, err, errlen);
        } else if (strcaseeq(k, "encode")) {
            if ((rc = want_args(c, 0, -1, err, errlen)) == 0) {
                buf_t b;
                buf_init(&b);
                for (int j = 1; j < c->nargs; j++) {
                    if (!(strcaseeq(c->args[j], "gzip") || strcaseeq(c->args[j], "zstd") || strcaseeq(c->args[j], "br"))) {
                        snprintf(err, errlen, "line %d: encode supports gzip, zstd and br", c->line);
                        rc = -1;
                        break;
                    }
                    if (j > 1)
                        buf_puts(&b, " ");
                    buf_puts(&b, c->args[j]);
                }
                if (rc == 0 && c->nargs == 1)
                    buf_puts(&b, "zstd br gzip");
                buf_append(&b, "", 1);
                free(s->encode);
                s->encode = xstrdup(b.data);
                buf_free(&b);
                for (int j = 0; j < c->nkids && rc == 0; j++) {
                    node_t *kk = c->kids[j];
                    if (strcaseeq(kk->args[0], "minimum_length") && kk->nargs == 2)
                        rc = arg_int(kk, 1, &s->encode_min, 0, 1 << 30, err, errlen);
                    else if (strcaseeq(kk->args[0], "gzip") || strcaseeq(kk->args[0], "zstd") || strcaseeq(kk->args[0], "br"))
                        ; /* level options are accepted and ignored */
                    else {
                        snprintf(err, errlen, "line %d: unknown encode option '%s'", kk->line, kk->args[0]);
                        rc = -1;
                    }
                }
            }
        } else {
            snprintf(err, errlen, "line %d: unknown directive '%s'", c->line, k);
            rc = -1;
        }
        if (rc < 0) {
            free(server_root);
            server_free(s);
            return -1;
        }
    }
    free(server_root);
    if (s->tls_mode == TLS_NONE && (s->tls_cert || s->tls_key)) {
        server_free(s);
        FAIL("line %d: incomplete tls configuration", d->line);
    }
    if (s->nroutes == 0) {
        server_free(s);
        FAIL("line %d: site block has no handlers (reverse_proxy, route, respond, file_server, ...)", d->line);
    }
    s->needs_body = (s->rl && template_needs_body(s->rl->key)) ? 1 : 0;
    for (int i = 0; i < s->n_hdr_up; i++)
        if (template_needs_body(s->hdr_up[i].value))
            s->needs_body = 1;
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
            /* admin <addr> { secret <s>; rate 6/m; burst 3; max_failures 5; ban 15m } */
            admin_cfg_t *a = &cfg->admin;
            if (c->nkids) {
                a->rate = 6.0 / 60.0;
                a->burst = 3;
                a->max_failures = 5;
                a->ban = 900;
            }
            for (int j = 0; j < c->nkids; j++) {
                node_t *o = c->kids[j];
                const char *n = o->args[0];
                int rc = 0;
                if (strcaseeq(n, "secret") || strcaseeq(n, "token")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0) {
                        if (strlen(o->args[1]) < 16) {
                            snprintf(err, errlen, "line %d: the admin secret must be at least 16 characters "
                                     "(e.g. the output of `openssl rand -hex 24`)", o->line);
                            rc = -1;
                        } else {
                            free(a->secret);
                            a->secret = xstrdup(o->args[1]);
                        }
                    }
                } else if (strcaseeq(n, "rate")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0) {
                        if (strcaseeq(o->args[1], "off"))
                            a->rate = 0;
                        else if (parse_rate(o->args[1], &a->rate) < 0) {
                            snprintf(err, errlen, "line %d: invalid admin rate '%s' (use e.g. 6/m, or off)", o->line, o->args[1]);
                            rc = -1;
                        }
                    }
                } else if (strcaseeq(n, "burst")) {
                    int v = 0;
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0 && (rc = arg_int(o, 1, &v, 1, 10000, err, errlen)) == 0)
                        a->burst = v;
                } else if (strcaseeq(n, "max_failures") || strcaseeq(n, "ban_threshold")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_int(o, 1, &a->max_failures, 0, 1000000, err, errlen);
                } else if (strcaseeq(n, "ban") || strcaseeq(n, "ban_duration")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_duration(o, 1, &a->ban, err, errlen);
                    if (rc == 0 && a->ban <= 0) {
                        snprintf(err, errlen, "line %d: ban must be a positive duration (use max_failures 0 to disable bans)", o->line);
                        rc = -1;
                    }
                } else {
                    snprintf(err, errlen, "line %d: unknown admin option '%s'", o->line, n);
                    rc = -1;
                }
                if (rc < 0)
                    return -1;
            }
        } else if (strcaseeq(k, "log_level") || strcaseeq(k, "log") || strcaseeq(k, "debug")) {
            const char *lv = c->nargs > 1 ? c->args[1] : "debug";
            if (strcaseeq(lv, "debug")) cfg->log_level = LOG_DEBUG;
            else if (strcaseeq(lv, "info")) cfg->log_level = LOG_INFO;
            else if (strcaseeq(lv, "warn") || strcaseeq(lv, "warning")) cfg->log_level = LOG_WARN;
            else if (strcaseeq(lv, "error")) cfg->log_level = LOG_ERROR;
            else FAIL("line %d: unknown log level '%s'", c->line, lv);
        } else if (strcaseeq(k, "max_connections")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            if (strcaseeq(c->args[1], "auto") || strcaseeq(c->args[1], "unlimited"))
                cfg->max_connections = 0;
            else if (arg_int(c, 1, &cfg->max_connections, 1, 10000000, err, errlen) < 0)
                return -1;
        } else if (strcaseeq(k, "pidfile")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            free(cfg->pidfile);
            cfg->pidfile = xstrdup(c->args[1]);
        } else if (strcaseeq(k, "grace") || strcaseeq(k, "grace_period")) {
            if (want_args(c, 1, 1, err, errlen) < 0 || arg_duration(c, 1, &cfg->grace, err, errlen) < 0)
                return -1;
        } else if (strcaseeq(k, "http_port")) {
            if (want_args(c, 1, 1, err, errlen) < 0 || arg_int(c, 1, &cfg->http_port, 1, 65535, err, errlen) < 0)
                return -1;
        } else if (strcaseeq(k, "https_port")) {
            if (want_args(c, 1, 1, err, errlen) < 0 || arg_int(c, 1, &cfg->https_port, 1, 65535, err, errlen) < 0)
                return -1;
        } else if (strcaseeq(k, "storage")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            free(cfg->storage);
            cfg->storage = xstrdup(c->args[1]);
        } else if (strcaseeq(k, "email")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            free(cfg->acme_email);
            cfg->acme_email = xstrdup(c->args[1]);
        } else if (strcaseeq(k, "acme_ca")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            free(cfg->acme_ca);
            cfg->acme_ca = xstrdup(c->args[1]);
        } else if (strcaseeq(k, "acme_ca_root")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            free(cfg->acme_ca_root);
            cfg->acme_ca_root = xstrdup(c->args[1]);
        } else if (strcaseeq(k, "acme_challenge")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            if (strcaseeq(c->args[1], "http-01") || strcaseeq(c->args[1], "http"))
                cfg->acme_challenge = 0;
            else if (strcaseeq(c->args[1], "tls-alpn-01") || strcaseeq(c->args[1], "tls-alpn"))
                cfg->acme_challenge = 1;
            else if (strcaseeq(c->args[1], "dns-01") || strcaseeq(c->args[1], "dns"))
                cfg->acme_challenge = 2;
            else
                FAIL("line %d: acme_challenge accepts http-01, tls-alpn-01 or dns-01", c->line);
        } else if (strcaseeq(k, "acme_dns_script")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            if (access(c->args[1], X_OK) != 0)
                FAIL("line %d: acme_dns_script '%s' is not executable", c->line, c->args[1]);
            free(cfg->acme_dns_script);
            cfg->acme_dns_script = xstrdup(c->args[1]);
        } else if (strcaseeq(k, "acme_dns_propagation")) {
            if (want_args(c, 1, 1, err, errlen) < 0 || arg_duration(c, 1, &cfg->acme_dns_propagation, err, errlen) < 0)
                return -1;
        } else if (strcaseeq(k, "cache_capacity") || strcaseeq(k, "cache_size")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            if (parse_size(c->args[1], &cfg->cache_capacity) < 0)
                FAIL("line %d: invalid cache_capacity '%s'", c->line, c->args[1]);
        } else if (strcaseeq(k, "resolvers")) {
            if (want_args(c, 1, 4, err, errlen) < 0)
                return -1;
            for (int i = 1; i < c->nargs; i++) {
                char host[64];
                snprintf(host, sizeof host, "%s", c->args[i]);
                char *colon = strchr(host, ':');
                if (colon)
                    *colon = 0;
                struct in_addr a4;
                if (inet_pton(AF_INET, host, &a4) != 1)
                    FAIL("line %d: resolvers takes IPv4 addresses like 10.0.0.2 or 10.0.0.2:5353", c->line);
                cfg->resolvers = xrealloc(cfg->resolvers, sizeof(char *) * (size_t)(cfg->nresolvers + 1));
                cfg->resolvers[cfg->nresolvers++] = xstrdup(c->args[i]);
            }
        } else if (strcaseeq(k, "auto_https")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            if (strcaseeq(c->args[1], "off"))
                cfg->acme_disabled = 1;
            else if (strcaseeq(c->args[1], "disable_redirects"))
                cfg->acme_disabled = 2;
            else if (strcaseeq(c->args[1], "on"))
                cfg->acme_disabled = 0;
            else
                FAIL("line %d: auto_https accepts off, on or disable_redirects", c->line);
        } else if (strcaseeq(k, "trusted_proxies") || strcaseeq(k, "trusted_proxy")) {
            if (want_args(c, 1, 256, err, errlen) < 0)
                return -1;
            for (int a = 1; a < c->nargs; a++) {
                struct sockaddr_storage ss;
                if (inet_pton(AF_INET, c->args[a], &((struct sockaddr_in *)&ss)->sin_addr) != 1 &&
                    inet_pton(AF_INET6, c->args[a], &((struct sockaddr_in6 *)&ss)->sin6_addr) != 1 &&
                    strchr(c->args[a], '/') == NULL)
                    FAIL("line %d: trusted_proxies needs an IP or CIDR, got '%s'", c->line, c->args[a]);
                cfg->trusted_proxies = xrealloc(cfg->trusted_proxies, (size_t)(cfg->ntrusted_proxies + 1) * sizeof(char *));
                cfg->trusted_proxies[cfg->ntrusted_proxies++] = xstrdup(c->args[a]);
            }
        } else if (strcaseeq(k, "ip_guard") || strcaseeq(k, "connection_guard")) {
            ipguard_cfg_t *g = &cfg->ipguard;
            g->enabled = 1;
            for (int j = 0; j < c->nkids; j++) {
                node_t *o = c->kids[j];
                const char *n = o->args[0];
                int rc = 0;
                if (strcaseeq(n, "max_conns_per_ip") || strcaseeq(n, "max_conns")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_int(o, 1, &g->max_conns_per_ip, 0, 10000000, err, errlen);
                } else if (strcaseeq(n, "conn_rate")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0 && parse_rate(o->args[1], &g->conn_rate) < 0) {
                        snprintf(err, errlen, "line %d: invalid conn_rate '%s' (use e.g. 50r/s, 600r/m)", o->line, o->args[1]);
                        rc = -1;
                    }
                } else if (strcaseeq(n, "conn_burst")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0) {
                        g->conn_burst = atof(o->args[1]);
                        if (g->conn_burst <= 0) {
                            snprintf(err, errlen, "line %d: conn_burst must be positive", o->line);
                            rc = -1;
                        }
                    }
                } else if (strcaseeq(n, "ban_threshold")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_int(o, 1, &g->ban_threshold, 1, 100000000, err, errlen);
                } else if (strcaseeq(n, "ban_window")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_duration(o, 1, &g->ban_window, err, errlen);
                } else if (strcaseeq(n, "ban_duration") || strcaseeq(n, "ban_for")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_duration(o, 1, &g->ban_duration, err, errlen);
                } else if (strcaseeq(n, "max_keys")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_int(o, 1, &g->max_keys, 1, 100000000, err, errlen);
                } else {
                    snprintf(err, errlen, "line %d: unknown ip_guard option '%s'", o->line, n);
                    rc = -1;
                }
                if (rc < 0)
                    return -1;
            }
            if (g->ban_window <= 0)
                g->ban_window = 10.0;
        } else if (strcaseeq(k, "auto_rollback") || strcaseeq(k, "reload_rollback")) {
            rollback_cfg_t *rb = &cfg->auto_rollback;
            rb->enabled = 1;
            rb->error_rate = 0.5;
            rb->window = 15.0;
            rb->min_requests = 20;
            rb->canary = 5;
            for (int j = 0; j < c->nkids; j++) {
                node_t *o = c->kids[j];
                const char *n = o->args[0];
                int rc = 0;
                if (strcaseeq(n, "error_rate") || strcaseeq(n, "errors")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0) {
                        char *end;
                        double v = strtod(o->args[1], &end);
                        if (*end == '%')
                            v /= 100.0;
                        if (end == o->args[1] || v <= 0 || v > 1) {
                            snprintf(err, errlen, "line %d: error_rate must be a share like 30%% or 0.3", o->line);
                            rc = -1;
                        } else {
                            rb->error_rate = v;
                        }
                    }
                } else if (strcaseeq(n, "window") || strcaseeq(n, "probation")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_duration(o, 1, &rb->window, err, errlen);
                } else if (strcaseeq(n, "min_requests")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_int(o, 1, &rb->min_requests, 1, 100000000, err, errlen);
                } else if (strcaseeq(n, "canary")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0) {
                        char *end;
                        double v = strtod(o->args[1], &end);
                        if (end == o->args[1] || (*end && strcmp(end, "%") != 0) || v <= 0 || v > 100) {
                            snprintf(err, errlen, "line %d: canary must be a percentage like 10%%", o->line);
                            rc = -1;
                        } else {
                            rb->canary = (int)(v + 0.5);
                        }
                    }
                } else {
                    snprintf(err, errlen, "line %d: unknown auto_rollback option '%s'", o->line, n);
                    rc = -1;
                }
                if (rc < 0)
                    return -1;
            }
        } else if (strcaseeq(k, "scale_up") || strcaseeq(k, "scale_hook")) {
            scale_cfg_t *s = &cfg->scale_up;
            s->enabled = 1;
            s->cooldown = 60.0;
            for (int j = 0; j < c->nkids; j++) {
                node_t *o = c->kids[j];
                const char *n = o->args[0];
                int rc = 0;
                if (strcaseeq(n, "requests") || strcaseeq(n, "rate")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0 && parse_rate(o->args[1], &s->requests) < 0) {
                        snprintf(err, errlen, "line %d: invalid requests rate '%s' (use e.g. 1000r/s)", o->line, o->args[1]);
                        rc = -1;
                    }
                } else if (strcaseeq(n, "connections") || strcaseeq(n, "conns")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_int(o, 1, &s->connections, 1, 100000000, err, errlen);
                } else if (strcaseeq(n, "sustain") || strcaseeq(n, "for")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_duration(o, 1, &s->sustain, err, errlen);
                } else if (strcaseeq(n, "cooldown")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0)
                        rc = arg_duration(o, 1, &s->cooldown, err, errlen);
                } else if (strcaseeq(n, "exec") || strcaseeq(n, "command")) {
                    if ((rc = want_args(o, 1, 1, err, errlen)) == 0) {
                        free(s->exec);
                        s->exec = xstrdup(o->args[1]);
                    }
                } else {
                    snprintf(err, errlen, "line %d: unknown scale_up option '%s'", o->line, n);
                    rc = -1;
                }
                if (rc < 0)
                    return -1;
            }
            if (!s->exec)
                FAIL("line %d: scale_up needs an `exec <command>`", c->line);
            /* without a threshold the hook runs only when called through POST /scale_up */
        } else if (strcaseeq(k, "http3")) {
            if (want_args(c, 0, 1, err, errlen) < 0)
                return -1;
            const char *v = c->nargs > 1 ? c->args[1] : "on";
            if (strcaseeq(v, "on"))
                cfg->http3 = 1;
            else if (strcaseeq(v, "off"))
                cfg->http3 = 0;
            else
                FAIL("line %d: http3 accepts on or off", c->line);
#ifndef LIMER_H3
            if (cfg->http3)
                LOGW("line %d: http3 is ignored: this build has no HTTP/3 support (needs ngtcp2, nghttp3 and GnuTLS)", c->line);
            cfg->http3 = 0;
#endif
        } else if (strcaseeq(k, "server_header") || strcaseeq(k, "server_tokens")) {
            if (want_args(c, 1, 1, err, errlen) < 0)
                return -1;
            free(cfg->server_header);
            cfg->server_header = (strcaseeq(c->args[1], "off") || strcaseeq(c->args[1], "none"))
                                 ? NULL : xstrdup(c->args[1]);
        } else {
            FAIL("line %d: unknown global option '%s'", c->line, k);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Certificates and implicit servers                                   */
/* ------------------------------------------------------------------ */

static int host_is_local(const char *h)
{
    size_t n = strlen(h);
    return strcasecmp(h, "localhost") == 0 || (n > 10 && strcasecmp(h + n - 10, ".localhost") == 0);
}

static int config_finish_tls(config_t *cfg, char *err, size_t errlen)
{
    for (int i = 0; i < cfg->nservers; i++) {
        server_t *s = cfg->servers[i];
        if (s->tls_mode == TLS_NONE)
            continue;
        if (s->tls_mode == TLS_FILES) {
            if (tls_init_server(s, err, errlen) < 0)
                return -1;
            continue;
        }
        if (s->tls_mode == TLS_INTERNAL) {
            if (tls_init_internal(s, err, errlen) < 0)
                return -1;
            continue;
        }
        /* TLS_AUTO: local names get internal certificates; public names use ACME
         * (managed by the certificate manager, which installs them into storage). */
        int all_local = s->nhosts > 0;
        for (int h = 0; h < s->nhosts; h++)
            if (!host_is_local(s->hosts[h]))
                all_local = 0;
        if (all_local || cfg->acme_disabled == 1 || s->nhosts == 0) {
            if (tls_init_internal(s, err, errlen) < 0)
                return -1;
            if (!all_local && s->nhosts)
                LOGW("site %s: automatic HTTPS is off; serving a self-signed certificate", s->hosts[0]);
            s->tls_mode = TLS_INTERNAL;
            continue;
        }
        /* ACME-managed: load the certificate from storage when present, else a
         * temporary self-signed one until the manager obtains it. */
        if (tls_init_internal(s, err, errlen) < 0)
            return -1;
        extern int acme_load_stored(config_t *cfg, server_t *s, char *err, size_t errlen);
        if (acme_load_stored(cfg, s, err, errlen) < 0)
            return -1;
    }
    return 0;
}

/* For every https site with hostnames, add an http listener that redirects
 * to https and answers ACME http-01 challenges (unless disabled or a site
 * already serves plain http on that port). */
static void config_add_redirect_servers(config_t *cfg)
{
    if (cfg->acme_disabled == 1)
        return;
    char bind[32];
    snprintf(bind, sizeof bind, ":%d", cfg->http_port);
    for (int i = 0, n = cfg->nservers; i < n; i++) {
        server_t *s = cfg->servers[i];
        if (s->tls_mode == TLS_NONE || s->nhosts == 0 || s->is_admin)
            continue;
        /* does a plain-http site already own this bind with any of these hosts (or catch-all)? */
        int covered = 0;
        for (int j = 0; j < cfg->nservers && !covered; j++) {
            server_t *o = cfg->servers[j];
            if (o->tls_mode != TLS_NONE || o->is_admin)
                continue;
            for (int a = 0; a < o->naddr && !covered; a++) {
                if (strcmp(o->addrs[a], bind) != 0)
                    continue;
                if (o->nhosts == 0 && !o->redirect_https) {
                    covered = 1;
                    break;
                }
                for (int h = 0; h < o->nhosts && !covered; h++)
                    for (int sh = 0; sh < s->nhosts; sh++)
                        if (strcasecmp(o->hosts[h], s->hosts[sh]) == 0)
                            covered = 1;
            }
        }
        if (covered)
            continue;
        server_t *r = server_new();
        r->redirect_https = 1;
        r->port = s->port;
        server_add_bind(r, bind);
        for (int h = 0; h < s->nhosts; h++)
            server_add_host(r, s->hosts[h]);
        /* the redirect handler is built in; give it a placeholder route */
        route_t *rt = xcalloc(1, sizeof *rt);
        rt->name = xstrdup("https_redirect");
        rt->kind = ROUTE_REDIRECT;
        rt->resp_status = cfg->acme_disabled == 2 ? 404 : 308;
        rt->resp_body = xstrdup("https://{host}{uri}");
        r->routes = xmalloc(sizeof(route_t *));
        r->routes[0] = rt;
        r->nroutes = 1;
        cfg->servers = xrealloc(cfg->servers, sizeof(server_t *) * (size_t)(cfg->nservers + 1));
        cfg->servers[cfg->nservers++] = r;
    }
}

/* ------------------------------------------------------------------ */
/* Entry points                                                        */
/* ------------------------------------------------------------------ */

static config_t *config_parse_in(const char *text, const char *path, const char *base_dir, char *err, size_t errlen)
{
    err[0] = 0;
    char *expanded = expand_env(text);
    node_t *root = parse_text_to_tree(expanded, err, errlen);
    free(expanded);
    if (!root)
        return NULL;

    /* collect snippets "(name) { ... }" */
    snippets_t sn = { NULL, NULL, 0 };
    for (int k = 0; k < root->nkids;) {
        node_t *d = root->kids[k];
        if (d->nargs == 1 && d->args[0][0] == '(' && d->args[0][strlen(d->args[0]) - 1] == ')') {
            size_t n = strlen(d->args[0]);
            sn.names = xrealloc(sn.names, sizeof(char *) * (size_t)(sn.n + 1));
            sn.bodies = xrealloc(sn.bodies, sizeof(node_t *) * (size_t)(sn.n + 1));
            sn.names[sn.n] = xstrndup(d->args[0] + 1, n - 2);
            sn.bodies[sn.n] = d;
            sn.n++;
            memmove(root->kids + k, root->kids + k + 1, sizeof(node_t *) * (size_t)(root->nkids - k - 1));
            root->nkids--;
            continue;
        }
        k++;
    }
    int rc = expand_imports(root, base_dir, &sn, 0, err, errlen);
    for (int i = 0; i < sn.n; i++) {
        free(sn.names[i]);
        node_free(sn.bodies[i]);
    }
    free(sn.names);
    free(sn.bodies);
    if (rc < 0) {
        node_free(root);
        return NULL;
    }

    config_t *cfg = xcalloc(1, sizeof *cfg);
    cfg->refs = 1;
    cfg->workers = 1;
    cfg->log_level = LOG_INFO;
    cfg->grace = 10;
    cfg->http_port = 80;
    cfg->https_port = 443;
    cfg->acme_dns_propagation = 10;
    cfg->path = xstrdup(path ? path : "<inline>");
    cfg->text = xstrdup(text);
    g_loading_cfg = cfg;

    for (int k = 0; k < root->nkids; k++) {
        node_t *d = root->kids[k];
        int r;
        if (d->nargs == 0) {
            if (k != 0) {
                snprintf(err, errlen, "line %d: global options block must come first", d->line);
                r = -1;
            } else {
                r = parse_global(cfg, d, err, errlen);
            }
        } else {
            r = parse_server(cfg, d, err, errlen);
        }
        if (r < 0) {
            node_free(root);
            g_loading_cfg = NULL;
            config_unref(cfg);
            return NULL;
        }
    }
    node_free(root);
    g_loading_cfg = NULL;
    if (cfg->nservers == 0) {
        snprintf(err, errlen, "no server blocks defined");
        config_unref(cfg);
        return NULL;
    }
    if (!cfg->storage) {
        const char *home = getenv("XDG_DATA_HOME");
        char buf[1024];
        if (home && *home)
            snprintf(buf, sizeof buf, "%s/limer", home);
        else if ((home = getenv("HOME")) && *home)
            snprintf(buf, sizeof buf, "%s/.local/share/limer", home);
        else
            snprintf(buf, sizeof buf, "/var/lib/limer");
        cfg->storage = xstrdup(buf);
    }
    if (!cfg->acme_ca)
        cfg->acme_ca = xstrdup("https://acme-v02.api.letsencrypt.org/directory");
    config_add_redirect_servers(cfg);
    config_resolve_dynamic(cfg);
    g_loading_cfg = NULL;
    overrides_apply(cfg);
    if (config_finish_tls(cfg, err, errlen) < 0) {
        config_unref(cfg);
        return NULL;
    }
    if (cfg->scale_up.enabled && cfg->scale_up.requests <= 0 && cfg->scale_up.connections <= 0 && !cfg->admin_addr) {
        snprintf(err, errlen, "scale_up needs a `requests` or `connections` threshold, or the admin API for POST /scale_up");
        config_unref(cfg);
        return NULL;
    }
    if (cfg->admin_addr && !cfg->admin.secret && !addr_is_loopback(cfg->admin_addr))
        LOGW("the admin API on %s has no secret: anyone who can reach it can reload, drain and reconfigure; "
             "add `admin %s { secret ... }`", cfg->admin_addr, cfg->admin_addr);
    if (cfg->admin_addr) {
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

config_t *config_parse(const char *text, const char *path, char *err, size_t errlen)
{
    return config_parse_in(text, path, ".", err, errlen);
}

config_t *config_load(const char *path, char *err, size_t errlen)
{
    char *text = read_file(path, err, errlen);
    if (!text)
        return NULL;
    char *dup = xstrdup(path);
    const char *dir = dirname(dup);
    config_t *cfg = config_parse_in(text, path, dir, err, errlen);
    free(dup);
    free(text);
    return cfg;
}

/* ------------------------------------------------------------------ */
/* Runtime overrides                                                   */
/* ------------------------------------------------------------------ */

typedef struct override {
    char hostport[300];
    int drained;   /* -1 unset */
    int weight;    /* -1 unset */
} override_t;

static int overrides_read(const config_t *cfg, override_t **out)
{
    char path[2048];
    snprintf(path, sizeof path, "%s/overrides.conf", cfg->storage);
    FILE *f = fopen(path, "r");
    *out = NULL;
    if (!f)
        return 0;
    override_t *list = NULL;
    int n = 0;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        override_t o;
        o.drained = o.weight = -1;
        char *save = NULL;
        char *tok = strtok_r(line, " \t\r\n", &save);
        if (!tok || *tok == '#')
            continue;
        snprintf(o.hostport, sizeof o.hostport, "%s", tok);
        while ((tok = strtok_r(NULL, " \t\r\n", &save))) {
            if (str_has_prefix(tok, "drained="))
                o.drained = atoi(tok + 8) ? 1 : 0;
            else if (str_has_prefix(tok, "weight="))
                o.weight = atoi(tok + 7);
        }
        list = xrealloc(list, sizeof(override_t) * (size_t)(n + 1));
        list[n++] = o;
    }
    fclose(f);
    *out = list;
    return n;
}

static int overrides_write(const config_t *cfg, override_t *list, int n)
{
    if (mkdir_p(cfg->storage) < 0)
        return -1;
    char path[2048], tmp[2060];
    snprintf(path, sizeof path, "%s/overrides.conf", cfg->storage);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return -1;
    fputs("# runtime upstream overrides written by the admin API\n", f);
    for (int i = 0; i < n; i++) {
        if (list[i].drained < 0 && list[i].weight < 0)
            continue;
        fprintf(f, "%s", list[i].hostport);
        if (list[i].drained >= 0)
            fprintf(f, " drained=%d", list[i].drained);
        if (list[i].weight >= 0)
            fprintf(f, " weight=%d", list[i].weight);
        fputc('\n', f);
    }
    fclose(f);
    return rename(tmp, path);
}

/* Apply stored overrides to every matching upstream of cfg. */
int overrides_apply(config_t *cfg)
{
    override_t *list;
    int n = overrides_read(cfg, &list);
    for (int o = 0; o < n; o++) {
        for (int i = 0; i < cfg->nservers; i++) {
            server_t *s = cfg->servers[i];
            for (int r = 0; r < s->nroutes; r++) {
                pool_t *p = s->routes[r]->pool;
                if (!p)
                    continue;
                int changed = 0;
                for (int k = 0; k < p->nups; k++) {
                    upstream_t *u = p->ups[k];
                    if (strcmp(u->hostport, list[o].hostport) != 0)
                        continue;
                    if (list[o].drained >= 0)
                        u->drained = list[o].drained;
                    if (list[o].weight > 0) {
                        u->weight = list[o].weight;
                        changed = 1;
                    }
                }
                if (changed) {
                    p->total_weight = 0;
                    for (int k = 0; k < p->nups; k++)
                        p->total_weight += p->ups[k]->weight;
                }
            }
        }
    }
    free(list);
    return n;
}

int overrides_apply_upstream(const config_t *cfg, upstream_t *u)
{
    override_t *list;
    int n = overrides_read(cfg, &list);
    int hit = 0;
    for (int o = 0; o < n; o++) {
        if (strcmp(u->hostport, list[o].hostport) != 0)
            continue;
        if (list[o].drained >= 0)
            u->drained = list[o].drained;
        if (list[o].weight > 0)
            u->weight = list[o].weight;
        hit = 1;
    }
    free(list);
    return hit;
}

int overrides_set(const config_t *cfg, const char *hostport, int drained, int weight, char *err, size_t errlen)
{
    override_t *list;
    int n = overrides_read(cfg, &list);
    int found = -1;
    for (int i = 0; i < n; i++)
        if (strcmp(list[i].hostport, hostport) == 0)
            found = i;
    if (found < 0) {
        list = xrealloc(list, sizeof(override_t) * (size_t)(n + 1));
        found = n++;
        snprintf(list[found].hostport, sizeof list[found].hostport, "%s", hostport);
        list[found].drained = list[found].weight = -1;
    }
    if (drained >= 0)
        list[found].drained = drained;
    if (weight >= 0)
        list[found].weight = weight;
    int rc = overrides_write(cfg, list, n);
    if (rc < 0)
        snprintf(err, errlen, "cannot write %s/overrides.conf: %s", cfg->storage, strerror(errno));
    free(list);
    return rc;
}

int overrides_clear(const config_t *cfg)
{
    char path[2048];
    snprintf(path, sizeof path, "%s/overrides.conf", cfg->storage);
    return unlink(path) == 0 || errno == ENOENT ? 0 : -1;
}

int overrides_list(const config_t *cfg, buf_t *json)
{
    override_t *list;
    int n = overrides_read(cfg, &list);
    buf_puts(json, "{\"overrides\":[");
    for (int i = 0; i < n; i++) {
        buf_printf(json, "%s{\"address\":\"%s\"", i ? "," : "", list[i].hostport);
        if (list[i].drained >= 0)
            buf_printf(json, ",\"drained\":%s", list[i].drained ? "true" : "false");
        if (list[i].weight >= 0)
            buf_printf(json, ",\"weight\":%d", list[i].weight);
        buf_puts(json, "}");
    }
    buf_puts(json, "]}\n");
    free(list);
    return n;
}
