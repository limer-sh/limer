/* match.c - request key extraction and route matchers */
#include "limer.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Look up `name` in a form-encoded string (a=b&c=d). Decoded value appended to out. */
static int form_lookup(const char *data, size_t len, const char *name, buf_t *out)
{
    size_t nl = strlen(name);
    size_t i = 0;
    while (i < len) {
        size_t start = i;
        while (i < len && data[i] != '&')
            i++;
        size_t end = i;
        if (i < len)
            i++; /* skip & */
        const char *eq = memchr(data + start, '=', end - start);
        size_t klen = eq ? (size_t)(eq - (data + start)) : end - start;
        char key[256];
        if (klen >= sizeof key)
            continue;
        int dk = url_decode(data + start, klen, key, sizeof key);
        if (dk < 0 || (size_t)dk != nl || memcmp(key, name, nl) != 0)
            continue;
        if (!eq)
            return 1; /* present with empty value */
        size_t vlen = end - (size_t)(eq + 1 - data);
        if (buf_reserve(out, vlen + 1) < 0)
            return 0;
        int dv = url_decode(eq + 1, vlen, buf_wptr(out), buf_wavail(out));
        if (dv < 0)
            return 0;
        buf_commit(out, (size_t)dv);
        return 1;
    }
    return 0;
}

/* Look up a cookie value from a Cookie header (a=b; c=d). */
static int cookie_lookup(const char *cookie, const char *name, buf_t *out)
{
    size_t nl = strlen(name);
    const char *p = cookie;
    while (*p) {
        while (*p == ' ' || *p == ';')
            p++;
        const char *start = p;
        while (*p && *p != ';')
            p++;
        const char *end = p;
        const char *eq = memchr(start, '=', (size_t)(end - start));
        if (!eq)
            continue;
        if ((size_t)(eq - start) == nl && memcmp(start, name, nl) == 0) {
            const char *v = eq + 1;
            const char *ve = end;
            while (ve > v && ve[-1] == ' ')
                ve--;
            buf_append(out, v, (size_t)(ve - v));
            return 1;
        }
    }
    return 0;
}

int key_extract(const keysrc_t *k, const req_ctx_t *ctx, buf_t *out)
{
    const http_req_t *r = ctx->req;
    buf_reset(out);
    switch (k->src) {
    case KS_CLIENT_IP:
        buf_puts(out, ctx->peer_ip);
        return 1;
    case KS_HEADER: {
        const char *v = http_hdr_get(r->hdrs, r->nhdr, k->name);
        if (!v)
            return 0;
        buf_puts(out, v);
        return 1;
    }
    case KS_COOKIE: {
        const char *c = http_hdr_get(r->hdrs, r->nhdr, "Cookie");
        return c ? cookie_lookup(c, k->name, out) : 0;
    }
    case KS_QUERY:
        return form_lookup(r->query, strlen(r->query), k->name, out);
    case KS_PATH:
        buf_puts(out, r->path);
        return 1;
    case KS_URI:
        buf_puts(out, r->uri);
        return 1;
    case KS_METHOD:
        buf_puts(out, r->method);
        return 1;
    case KS_HOST: {
        const char *v = http_hdr_get(r->hdrs, r->nhdr, "Host");
        if (!v)
            return 0;
        /* strip port */
        const char *colon = strrchr(v, ':');
        if (colon && !strchr(colon, ']'))
            buf_append(out, v, (size_t)(colon - v));
        else
            buf_puts(out, v);
        return 1;
    }
    case KS_JSON: {
        size_t bl = buf_readable(&r->body);
        if (bl == 0)
            return 0;
        int t = json_extract(buf_rptr(&r->body), bl, k->name, out);
        return t != JSON_NONE && t != JSON_NULL;
    }
    case KS_FORM:
        return form_lookup(buf_rptr(&r->body), buf_readable(&r->body), k->name, out);
    case KS_BODY:
        if (buf_readable(&r->body) == 0)
            return 0;
        buf_append(out, buf_rptr(&r->body), buf_readable(&r->body));
        return 1;
    case KS_TLS_CLIENT: {
        const tls_client_info_t *ci = ctx->client_cert;
        if (!ci)
            return 0;
        const char *f = k->name ? k->name : "subject";
        if (strcasecmp(f, "verified") == 0) {
            buf_puts(out, ci->present && ci->verified ? "true" : "false");
            return 1;
        }
        if (strcasecmp(f, "present") == 0) {
            buf_puts(out, ci->present ? "true" : "false");
            return 1;
        }
        if (!ci->present)
            return 0;
        if (strcasecmp(f, "subject") == 0)
            buf_puts(out, ci->subject);
        else if (strcasecmp(f, "issuer") == 0)
            buf_puts(out, ci->issuer);
        else if (strcasecmp(f, "serial") == 0)
            buf_puts(out, ci->serial);
        else if (strcasecmp(f, "fingerprint") == 0)
            buf_puts(out, ci->fingerprint);
        else
            return 0;
        return 1;
    }
    default:
        return 0;
    }
}

static int eval_values(const matcher_t *m, const char *v, size_t vlen)
{
    /* value-list ops are OR'ed; negative ops are AND'ed via De Morgan */
    switch (m->op) {
    case OP_EXISTS:
        return 1;
    case OP_MISSING:
        return 0;
    case OP_EQ:
        for (int i = 0; i < m->nvals; i++) {
            if (m->key.src == KS_PATH || m->key.src == KS_HOST) {
                if (glob_match(m->vals[i], v))
                    return 1;
            } else if (strlen(m->vals[i]) == vlen && memcmp(m->vals[i], v, vlen) == 0) {
                return 1;
            } else if (m->key.src == KS_METHOD && strcasecmp(m->vals[i], v) == 0) {
                return 1;
            }
        }
        return 0;
    case OP_NE:
        for (int i = 0; i < m->nvals; i++) {
            if (m->key.src == KS_PATH || m->key.src == KS_HOST) {
                if (glob_match(m->vals[i], v))
                    return 0;
            } else if (strlen(m->vals[i]) == vlen && memcmp(m->vals[i], v, vlen) == 0) {
                return 0;
            }
        }
        return 1;
    case OP_PREFIX:
        for (int i = 0; i < m->nvals; i++)
            if (str_has_prefix(v, m->vals[i]))
                return 1;
        return 0;
    case OP_CONTAINS:
        for (int i = 0; i < m->nvals; i++)
            if (memmem(v, vlen, m->vals[i], strlen(m->vals[i])))
                return 1;
        return 0;
    case OP_RE:
        for (int i = 0; i < m->nvals; i++)
            if (regexec(&m->re[i], v, 0, NULL, 0) == 0)
                return 1;
        return 0;
    case OP_NRE:
        for (int i = 0; i < m->nvals; i++)
            if (regexec(&m->re[i], v, 0, NULL, 0) == 0)
                return 0;
        return 1;
    case OP_GT: case OP_LT: case OP_GE: case OP_LE: {
        double x;
        if (!is_numeric(v, &x))
            return 0;
        for (int i = 0; i < m->nvals; i++) {
            double y = m->nums[i];
            int ok = m->op == OP_GT ? x > y : m->op == OP_LT ? x < y : m->op == OP_GE ? x >= y : x <= y;
            if (ok)
                return 1;
        }
        return 0;
    }
    }
    return 0;
}

int matcher_eval(const matcher_t *m, const req_ctx_t *ctx)
{
    int res;
    if (m->key.src == KS_CLIENT_IP) {
        /* remote_ip matcher uses CIDR semantics */
        res = 0;
        if (m->op == OP_EQ || m->op == OP_NE) {
            for (int i = 0; i < m->nvals; i++)
                if (cidr_match(m->vals[i], ctx->peer)) {
                    res = 1;
                    break;
                }
            if (m->op == OP_NE)
                res = !res;
        } else {
            buf_t tmp;
            buf_init(&tmp);
            buf_puts(&tmp, ctx->peer_ip);
            buf_append(&tmp, "", 1);
            res = eval_values(m, buf_rptr(&tmp), buf_readable(&tmp) - 1);
            buf_free(&tmp);
        }
        return m->negate ? !res : res;
    }
    buf_t v;
    buf_init(&v);
    int present = key_extract(&m->key, ctx, &v);
    if (!present) {
        res = (m->op == OP_MISSING || m->op == OP_NE || m->op == OP_NRE);
    } else {
        buf_append(&v, "", 1); /* NUL-terminate for regex/strtod */
        res = eval_values(m, buf_rptr(&v), buf_readable(&v) - 1);
    }
    buf_free(&v);
    return m->negate ? !res : res;
}

int route_matches(const route_t *r, const req_ctx_t *ctx)
{
    for (int i = 0; i < r->nm; i++)
        if (!matcher_eval(&r->m[i], ctx))
            return 0;
    return 1;
}

/* ---- does evaluating this read the request body? (decides body streaming) ---- */

int keysrc_needs_body(const keysrc_t *k)
{
    return k->src == KS_JSON || k->src == KS_FORM || k->src == KS_BODY;
}

int template_needs_body(const char *tmpl)
{
    if (!tmpl)
        return 0;
    return strstr(tmpl, "{json.") != NULL || strstr(tmpl, "{form.") != NULL || strstr(tmpl, "{body}") != NULL;
}

static int hdr_ops_need_body(const hdr_op_t *ops, int n)
{
    for (int i = 0; i < n; i++)
        if (template_needs_body(ops[i].value))
            return 1;
    return 0;
}

int route_compute_needs_body(route_t *r)
{
    int need = 0;
    for (int i = 0; i < r->nm; i++)
        if (keysrc_needs_body(&r->m[i].key))
            need = 1;
    if (r->pool) {
        if (r->pool->policy == LB_HASH && keysrc_needs_body(&r->pool->key))
            need = 1;
        if (hdr_ops_need_body(r->pool->hdr_up, r->pool->n_hdr_up))
            need = 1;
    }
    if (r->rl && template_needs_body(r->rl->key))
        need = 1;
    for (int i = 0; i < r->nrw; i++)
        if (template_needs_body(r->rw[i].a) || template_needs_body(r->rw[i].b))
            need = 1;
    if (hdr_ops_need_body(r->hdr_down, r->n_hdr_down))
        need = 1;
    r->needs_body = need;
    return need;
}

/* Match without the body: 0 cannot match, 1 matches, 2 undecided until the body is read. */
int route_prematch(const route_t *r, const req_ctx_t *ctx)
{
    int undecided = 0;
    for (int i = 0; i < r->nm; i++) {
        if (keysrc_needs_body(&r->m[i].key)) {
            undecided = 1;
            continue;
        }
        if (!matcher_eval(&r->m[i], ctx))
            return 0;
    }
    return (undecided || r->needs_body) ? 2 : 1;
}
