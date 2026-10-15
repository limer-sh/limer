/* balance.c - upstream selection policies and passive health accounting */
#include "limer.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

const char *lb_policy_name(int p)
{
    switch (p) {
    case LB_ROUND_ROBIN: return "round_robin";
    case LB_LEAST_CONN: return "least_conn";
    case LB_RANDOM: return "random";
    case LB_FIRST: return "first";
    case LB_HASH: return "hash";
    case LB_STICKY: return "sticky_cookie";
    }
    return "?";
}

const char *keysrc_name(int s)
{
    switch (s) {
    case KS_NONE: return "none";
    case KS_CLIENT_IP: return "client_ip";
    case KS_HEADER: return "header";
    case KS_COOKIE: return "cookie";
    case KS_QUERY: return "query";
    case KS_PATH: return "path";
    case KS_URI: return "uri";
    case KS_JSON: return "json";
    case KS_FORM: return "form";
    case KS_BODY: return "body";
    case KS_METHOD: return "method";
    case KS_HOST: return "host";
    case KS_TLS_CLIENT: return "tls_client";
    }
    return "?";
}

int upstream_healthy(const upstream_t *u, double now)
{
    if (u->drained)
        return 0;
    if (u->admit_at > now)   /* a discovered member settling before it takes traffic */
        return 0;
    if (u->hc_status < 0)
        return 0;
    if (u->fail_until > now)
        return 0;
    return 1;
}

static upstream_t *pick_wrr(pool_t *p, uint64_t tried, double now, int *idx)
{
    /* smooth weighted round robin (nginx algorithm) over eligible upstreams */
    int best = -1, total = 0;
    for (int i = 0; i < p->nups; i++) {
        upstream_t *u = p->ups[i];
        if ((tried >> i) & 1 || !upstream_healthy(u, now))
            continue;
        u->cur_weight += u->weight;
        total += u->weight;
        if (best < 0 || u->cur_weight > p->ups[best]->cur_weight)
            best = i;
    }
    if (best < 0)
        return NULL;
    p->ups[best]->cur_weight -= total;
    *idx = best;
    return p->ups[best];
}

static upstream_t *pick_least_conn(pool_t *p, uint64_t tried, double now, int *idx)
{
    int best = -1;
    double best_score = 0;
    int ties = 0;
    for (int i = 0; i < p->nups; i++) {
        upstream_t *u = p->ups[i];
        if ((tried >> i) & 1 || !upstream_healthy(u, now))
            continue;
        double score = (double)u->active / (double)(u->weight > 0 ? u->weight : 1);
        if (best < 0 || score < best_score) {
            best = i;
            best_score = score;
            ties = 1;
        } else if (score == best_score) {
            /* reservoir sampling among ties for fairness */
            ties++;
            if (rand() % ties == 0)
                best = i;
        }
    }
    if (best < 0)
        return NULL;
    *idx = best;
    return p->ups[best];
}

static upstream_t *pick_random(pool_t *p, uint64_t tried, double now, int *idx)
{
    int total = 0;
    for (int i = 0; i < p->nups; i++)
        if (!((tried >> i) & 1) && upstream_healthy(p->ups[i], now))
            total += p->ups[i]->weight;
    if (total <= 0)
        return NULL;
    int r = rand() % total;
    for (int i = 0; i < p->nups; i++) {
        if ((tried >> i) & 1 || !upstream_healthy(p->ups[i], now))
            continue;
        r -= p->ups[i]->weight;
        if (r < 0) {
            *idx = i;
            return p->ups[i];
        }
    }
    return NULL;
}

static upstream_t *pick_first(pool_t *p, uint64_t tried, double now, int *idx)
{
    for (int i = 0; i < p->nups; i++)
        if (!((tried >> i) & 1) && upstream_healthy(p->ups[i], now)) {
            *idx = i;
            return p->ups[i];
        }
    return NULL;
}

/*
 * Weighted rendezvous (highest random weight) hashing: every upstream gets a
 * score derived from hash(key, upstream); the highest wins. Adding or removing
 * an upstream only moves the keys that belonged to it, and unhealthy upstreams
 * are skipped so their keys fall through to the next-best candidate.
 */
static upstream_t *pick_hash(pool_t *p, const char *key, size_t keylen, uint64_t tried, double now, int *idx)
{
    int best = -1;
    double best_score = -INFINITY;
    for (int i = 0; i < p->nups; i++) {
        upstream_t *u = p->ups[i];
        if ((tried >> i) & 1 || !upstream_healthy(u, now))
            continue;
        uint64_t seed = hash64(u->hostport, strlen(u->hostport));
        uint64_t h = hash64_seed(key, keylen, seed);
        /* map to (0,1) and apply weight: score = -w / ln(u) */
        double unit = ((double)(h >> 11) + 1.0) / 9007199254740993.0; /* 2^53 + 1 */
        double score = -(double)(u->weight > 0 ? u->weight : 1) / log(unit);
        if (score > best_score) {
            best_score = score;
            best = i;
        }
    }
    if (best < 0)
        return NULL;
    *idx = best;
    return p->ups[best];
}

upstream_t *pool_select(pool_t *p, const req_ctx_t *ctx, uint64_t tried, double now, int *idx_out, char *why, size_t whylen)
{
    int idx = -1;
    upstream_t *u = NULL;
    if (why && whylen)
        why[0] = 0;
    switch (p->policy) {
    case LB_HASH: {
        buf_t key;
        buf_init(&key);
        if (ctx && key_extract(&p->key, ctx, &key) && buf_readable(&key) > 0) {
            u = pick_hash(p, buf_rptr(&key), buf_readable(&key), tried, now, &idx);
            if (why) {
                size_t kl = buf_readable(&key);
                snprintf(why, whylen, "hash(%s%s%s=%.*s)", keysrc_name(p->key.src),
                         p->key.name ? ":" : "", p->key.name ? p->key.name : "",
                         (int)(kl > 40 ? 40 : kl), buf_rptr(&key));
            }
        } else {
            u = pick_wrr(p, tried, now, &idx);
            if (why)
                snprintf(why, whylen, "hash(key missing; round_robin)");
        }
        buf_free(&key);
        break;
    }
    case LB_STICKY: {
        /* the cookie names the upstream; fall back to round robin when it is
         * missing, unknown or points at an unhealthy upstream */
        buf_t key;
        buf_init(&key);
        if (ctx && key_extract(&p->key, ctx, &key) && buf_readable(&key) == 16) {
            for (int i = 0; i < p->nups; i++) {
                if ((tried >> i) & 1 || !upstream_healthy(p->ups[i], now))
                    continue;
                if (memcmp(p->ups[i]->sticky_id, buf_rptr(&key), 16) == 0) {
                    u = p->ups[i];
                    idx = i;
                    break;
                }
            }
        }
        if (u) {
            if (why)
                snprintf(why, whylen, "sticky_cookie");
        } else {
            u = pick_wrr(p, tried, now, &idx);
            if (why)
                snprintf(why, whylen, "sticky_cookie(new; round_robin)");
        }
        buf_free(&key);
        break;
    }
    case LB_LEAST_CONN:
        u = pick_least_conn(p, tried, now, &idx);
        break;
    case LB_RANDOM:
        u = pick_random(p, tried, now, &idx);
        break;
    case LB_FIRST:
        u = pick_first(p, tried, now, &idx);
        break;
    case LB_ROUND_ROBIN:
    default:
        u = pick_wrr(p, tried, now, &idx);
        break;
    }
    if (why && !why[0])
        snprintf(why, whylen, "%s", lb_policy_name(p->policy));
    if (idx_out)
        *idx_out = idx;
    return u;
}

void upstream_report_failure(pool_t *p, upstream_t *u, double now, const char *reason)
{
    u->failures++;
    if (p->max_fails <= 0)
        return;
    u->fails++;
    if (u->fails >= p->max_fails) {
        u->fail_until = now + p->fail_timeout;
        u->fails = 0;
        LOGW("upstream %s marked down for %.0fs after %d failures (%s)", u->hostport, p->fail_timeout, p->max_fails, reason);
    } else {
        LOGD("upstream %s failure %d/%d (%s)", u->hostport, u->fails, p->max_fails, reason);
    }
}

void upstream_report_success(pool_t *p, upstream_t *u)
{
    (void)p;
    u->fails = 0;
    u->responses++;
}
