/*
 * ipguard.c - per-source-IP admission control for L7 DoS mitigation.
 *
 * Applied at accept() time, before any HTTP parsing, so an abusive source is
 * turned away as cheaply as possible. Three independent controls, any subset
 * of which can be enabled from the `ip_guard { }` global block:
 *
 *   - max_conns_per_ip : cap concurrent connections from one address
 *   - conn_rate        : token-bucket limit on NEW connections per address
 *   - automatic banning: an address that trips the above `ban_threshold`
 *                        times within `ban_window` is refused outright for
 *                        `ban_duration`
 *
 * State is per worker (like rate_limit zones): with `workers N` the limits
 * apply per process. The table is keyed by the exact client IP string.
 */
#include "limer.h"
#include <stdlib.h>
#include <string.h>

typedef struct ipg_entry {
    uint64_t hash;
    char   ip[64];
    int    conns;          /* current concurrent connections */
    double tokens;         /* new-connection token bucket */
    double last;           /* last refill time */
    double banned_until;   /* 0 = not banned */
    int    strikes;        /* strikes in the current window */
    double strike_start;   /* start of the current strike window */
    struct ipg_entry *next;
} ipg_entry_t;

struct ipguard {
    int nbuckets;
    int nkeys;
    ipg_entry_t **buckets;
    uint64_t admitted;
    uint64_t refused_conn;
    uint64_t refused_rate;
    uint64_t refused_ban;
    uint64_t bans;
};

ipguard_t *ipguard_new(int max_keys)
{
    ipguard_t *g = xcalloc(1, sizeof *g);
    if (max_keys <= 0)
        max_keys = 1000000;
    g->nbuckets = 4096;
    while (g->nbuckets < max_keys / 2)
        g->nbuckets *= 2;
    g->buckets = xcalloc((size_t)g->nbuckets, sizeof(ipg_entry_t *));
    return g;
}

void ipguard_free(ipguard_t *g)
{
    if (!g)
        return;
    for (int i = 0; i < g->nbuckets; i++) {
        ipg_entry_t *e = g->buckets[i];
        while (e) {
            ipg_entry_t *n = e->next;
            free(e);
            e = n;
        }
    }
    free(g->buckets);
    free(g);
}

static ipg_entry_t *ipg_find(ipguard_t *g, const char *ip, uint64_t h)
{
    ipg_entry_t *e = g->buckets[h & (uint64_t)(g->nbuckets - 1)];
    while (e && !(e->hash == h && strcmp(e->ip, ip) == 0))
        e = e->next;
    return e;
}

/* Drop entries that hold no connections, carry no live ban, and have sat idle
 * long enough that their bucket would be full again anyway. */
static void ipguard_sweep(ipguard_t *g, const ipguard_cfg_t *cfg, double now)
{
    double idle = 1.0;
    if (cfg->conn_rate > 0) {
        double burst = cfg->conn_burst > 0 ? cfg->conn_burst : cfg->conn_rate;
        idle = burst / cfg->conn_rate + 1.0;
    }
    for (int i = 0; i < g->nbuckets; i++) {
        ipg_entry_t **pp = &g->buckets[i];
        while (*pp) {
            ipg_entry_t *e = *pp;
            if (e->conns == 0 && e->banned_until <= now && now - e->last > idle) {
                *pp = e->next;
                free(e);
                g->nkeys--;
            } else {
                pp = &e->next;
            }
        }
    }
}

static ipg_entry_t *ipg_get(ipguard_t *g, const ipguard_cfg_t *cfg, const char *ip, double now)
{
    uint64_t h = hash64(ip, strlen(ip));
    ipg_entry_t *e = ipg_find(g, ip, h);
    if (e)
        return e;
    int max_keys = cfg->max_keys > 0 ? cfg->max_keys : 1000000;
    if (g->nkeys >= max_keys) {
        ipguard_sweep(g, cfg, now);
        if (g->nkeys >= max_keys) {
            /* evict a connection-free, unbanned entry from this chain */
            ipg_entry_t **pp = &g->buckets[h & (uint64_t)(g->nbuckets - 1)];
            while (*pp && ((*pp)->conns > 0 || (*pp)->banned_until > now))
                pp = &(*pp)->next;
            if (*pp) {
                ipg_entry_t *v = *pp;
                *pp = v->next;
                free(v);
                g->nkeys--;
            }
            /* if the whole chain is busy we allocate anyway: never refuse a
             * legitimate connection just because the table is full. */
        }
    }
    e = xcalloc(1, sizeof *e);
    e->hash = h;
    snprintf(e->ip, sizeof e->ip, "%s", ip);
    e->tokens = cfg->conn_burst > 0 ? cfg->conn_burst : cfg->conn_rate;
    e->last = now;
    ipg_entry_t **head = &g->buckets[h & (uint64_t)(g->nbuckets - 1)];
    e->next = *head;
    *head = e;
    g->nkeys++;
    return e;
}

/* Record a strike against an address; ban it once it trips the threshold
 * within the window. */
static void ipg_strike(ipguard_t *g, const ipguard_cfg_t *cfg, ipg_entry_t *e, double now)
{
    if (cfg->ban_threshold <= 0 || cfg->ban_duration <= 0)
        return;
    double window = cfg->ban_window > 0 ? cfg->ban_window : 10.0;
    if (e->strike_start == 0 || now - e->strike_start > window) {
        e->strike_start = now;
        e->strikes = 0;
    }
    e->strikes++;
    if (e->strikes >= cfg->ban_threshold) {
        e->banned_until = now + cfg->ban_duration;
        e->strikes = 0;
        e->strike_start = 0;
        g->bans++;
        LOGW("ipguard: banned %s for %.0fs after %d strikes", e->ip,
             cfg->ban_duration, cfg->ban_threshold);
    }
}

int ipguard_admit(ipguard_t *g, const ipguard_cfg_t *cfg, const char *ip, double now)
{
    ipg_entry_t *e = ipg_get(g, cfg, ip, now);

    if (e->banned_until > now) {
        g->refused_ban++;
        return IPGUARD_BANNED;
    }
    e->banned_until = 0;   /* ban expired: let it be swept later */

    if (cfg->max_conns_per_ip > 0 && e->conns >= cfg->max_conns_per_ip) {
        ipg_strike(g, cfg, e, now);
        g->refused_conn++;
        return IPGUARD_CONN_LIMIT;
    }

    if (cfg->conn_rate > 0) {
        double burst = cfg->conn_burst > 0 ? cfg->conn_burst : cfg->conn_rate;
        double elapsed = now - e->last;
        if (elapsed > 0) {
            e->tokens += elapsed * cfg->conn_rate;
            if (e->tokens > burst)
                e->tokens = burst;
            e->last = now;
        }
        if (e->tokens < 1.0) {
            ipg_strike(g, cfg, e, now);
            g->refused_rate++;
            return IPGUARD_RATE;
        }
        e->tokens -= 1.0;
    }

    e->conns++;
    g->admitted++;
    return IPGUARD_OK;
}

void ipguard_release(ipguard_t *g, const char *ip)
{
    uint64_t h = hash64(ip, strlen(ip));
    ipg_entry_t *e = ipg_find(g, ip, h);
    if (e && e->conns > 0)
        e->conns--;
}

/* Is this address currently banned? Counts a refusal when it is, since a true
 * result always leads the caller to turn the request away. */
int ipguard_is_banned(ipguard_t *g, const char *ip, double now)
{
    uint64_t h = hash64(ip, strlen(ip));
    ipg_entry_t *e = ipg_find(g, ip, h);
    if (e && e->banned_until > now) {
        g->refused_ban++;
        return 1;
    }
    return 0;
}

/* Record a request-level strike against an address (e.g. a rate-limit
 * rejection), banning it once it trips the threshold within the window. */
void ipguard_strike(ipguard_t *g, const ipguard_cfg_t *cfg, const char *ip, double now)
{
    if (cfg->ban_threshold <= 0 || cfg->ban_duration <= 0)
        return;
    ipg_entry_t *e = ipg_get(g, cfg, ip, now);
    ipg_strike(g, cfg, e, now);
}

void ipguard_stats(const ipguard_t *g, uint64_t *admitted, uint64_t *ref_conn,
                   uint64_t *ref_rate, uint64_t *ref_ban, uint64_t *bans, int *tracked)
{
    if (admitted) *admitted = g->admitted;
    if (ref_conn) *ref_conn = g->refused_conn;
    if (ref_rate) *ref_rate = g->refused_rate;
    if (ref_ban)  *ref_ban  = g->refused_ban;
    if (bans)     *bans     = g->bans;
    if (tracked)  *tracked  = g->nkeys;
}
