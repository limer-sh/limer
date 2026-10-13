/* ratelimit.c - token-bucket rate limiting keyed by an arbitrary string */
#include "limer.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

typedef struct rl_entry {
    uint64_t hash;
    char *key;
    double tokens;
    double last;
    struct rl_entry *next;
} rl_entry_t;

struct ratelimit {
    double rate;        /* tokens per second */
    double burst;       /* bucket capacity */
    int max_keys;
    int nkeys;
    int nbuckets;
    rl_entry_t **buckets;
    uint64_t hits, limited;
};

ratelimit_t *ratelimit_new(double rate, double burst, int max_keys)
{
    ratelimit_t *rl = xcalloc(1, sizeof *rl);
    rl->rate = rate;
    rl->burst = burst > 0 ? burst : rate;
    rl->max_keys = max_keys > 0 ? max_keys : 100000;
    rl->nbuckets = 4096;
    while (rl->nbuckets < rl->max_keys / 2)
        rl->nbuckets *= 2;
    rl->buckets = xcalloc((size_t)rl->nbuckets, sizeof(rl_entry_t *));
    return rl;
}

void ratelimit_free(ratelimit_t *rl)
{
    if (!rl)
        return;
    for (int i = 0; i < rl->nbuckets; i++) {
        rl_entry_t *e = rl->buckets[i];
        while (e) {
            rl_entry_t *n = e->next;
            free(e->key);
            free(e);
            e = n;
        }
    }
    free(rl->buckets);
    free(rl);
}

/* Drop entries that have been idle long enough to be full again. */
static void ratelimit_sweep(ratelimit_t *rl, double now)
{
    double idle = rl->burst / rl->rate + 1.0;
    for (int i = 0; i < rl->nbuckets; i++) {
        rl_entry_t **pp = &rl->buckets[i];
        while (*pp) {
            rl_entry_t *e = *pp;
            if (now - e->last > idle) {
                *pp = e->next;
                free(e->key);
                free(e);
                rl->nkeys--;
            } else {
                pp = &e->next;
            }
        }
    }
}

/* Returns 1 when the request is allowed. When limited, *retry_after is the
 * number of seconds until one token is available. */
int ratelimit_check(ratelimit_t *rl, const char *key, double now, double *retry_after)
{
    uint64_t h = hash64(key, strlen(key));
    rl_entry_t **head = &rl->buckets[h & (uint64_t)(rl->nbuckets - 1)];
    rl_entry_t *e = *head;
    while (e && !(e->hash == h && strcmp(e->key, key) == 0))
        e = e->next;
    if (!e) {
        if (rl->nkeys >= rl->max_keys) {
            ratelimit_sweep(rl, now);
            if (rl->nkeys >= rl->max_keys) {
                /* table is genuinely full of active keys: evict one from this chain */
                rl_entry_t *victim = *head;
                if (victim) {
                    *head = victim->next;
                    free(victim->key);
                    free(victim);
                    rl->nkeys--;
                }
            }
        }
        e = xcalloc(1, sizeof *e);
        e->hash = h;
        e->key = xstrdup(key);
        e->tokens = rl->burst;
        e->last = now;
        e->next = *head;
        *head = e;
        rl->nkeys++;
    }
    /* refill */
    double elapsed = now - e->last;
    if (elapsed > 0) {
        e->tokens += elapsed * rl->rate;
        if (e->tokens > rl->burst)
            e->tokens = rl->burst;
        e->last = now;
    }
    rl->hits++;
    if (e->tokens >= 1.0) {
        e->tokens -= 1.0;
        return 1;
    }
    rl->limited++;
    if (retry_after)
        *retry_after = (1.0 - e->tokens) / rl->rate;
    return 0;
}

void ratelimit_stats(const ratelimit_t *rl, uint64_t *hits, uint64_t *limited, int *keys)
{
    *hits = rl->hits;
    *limited = rl->limited;
    *keys = rl->nkeys;
}

double ratelimit_rate(const ratelimit_t *rl)
{
    return rl->rate;
}
