/*
 * cache.c - in-memory HTTP response cache (per worker).
 *
 * Entries store the identity entity as received from the upstream: a status,
 * the end-to-end headers and the full body. Serving applies the client's own
 * framing and compression, so one stored copy serves gzip, br and plain
 * clients alike. Keys are strings (method + scheme + host + target + the
 * values of the response's Vary headers); a bounded LRU list caps total
 * memory. Freshness, validators and stale-while-revalidate live on the entry
 * so the proxy can decide hit / revalidate / miss.
 */
#include "limer.h"
#include <stdlib.h>
#include <string.h>

typedef struct cache_hdr {
    char *name;
    char *value;
} cache_hdr_t;

struct cache_entry {
    char *key;
    uint64_t hash;
    int status;
    char *reason;
    cache_hdr_t *hdrs;
    int nhdr;
    char *body;
    size_t body_len;
    char *vary;             /* the response's Vary header */
    char *vary_val;         /* the request's Vary'd header values at store time */
    double stored_at;       /* wall clock */
    double ttl;             /* fresh for this many seconds */
    double swr;             /* extra seconds it may be served stale while revalidating */
    char *etag;
    char *last_modified;
    int revalidating;       /* a background refresh is in flight: do not evict */
    size_t size;            /* accounted bytes */
    struct cache_entry *hnext;      /* hash bucket chain */
    struct cache_entry *lru_prev, *lru_next;
};

struct cache {
    cache_entry_t **buckets;
    int nbuckets;
    int count;
    size_t size;
    size_t capacity;
    cache_entry_t *lru_head, *lru_tail;   /* head = most recently used */
    uint64_t hits, misses, stores, evictions, revalidations;
};

cache_t *cache_new(size_t capacity)
{
    cache_t *c = xcalloc(1, sizeof *c);
    c->nbuckets = 1024;
    c->buckets = xcalloc((size_t)c->nbuckets, sizeof(cache_entry_t *));
    c->capacity = capacity;
    return c;
}

static void entry_free(cache_entry_t *e)
{
    for (int i = 0; i < e->nhdr; i++) {
        free(e->hdrs[i].name);
        free(e->hdrs[i].value);
    }
    free(e->hdrs);
    free(e->key);
    free(e->reason);
    free(e->body);
    free(e->vary);
    free(e->vary_val);
    free(e->etag);
    free(e->last_modified);
    free(e);
}

static void lru_unlink(cache_t *c, cache_entry_t *e)
{
    if (e->lru_prev)
        e->lru_prev->lru_next = e->lru_next;
    else
        c->lru_head = e->lru_next;
    if (e->lru_next)
        e->lru_next->lru_prev = e->lru_prev;
    else
        c->lru_tail = e->lru_prev;
    e->lru_prev = e->lru_next = NULL;
}

static void lru_push_front(cache_t *c, cache_entry_t *e)
{
    e->lru_prev = NULL;
    e->lru_next = c->lru_head;
    if (c->lru_head)
        c->lru_head->lru_prev = e;
    c->lru_head = e;
    if (!c->lru_tail)
        c->lru_tail = e;
}

static void hash_unlink(cache_t *c, cache_entry_t *e)
{
    cache_entry_t **pp = &c->buckets[e->hash % (uint64_t)c->nbuckets];
    while (*pp) {
        if (*pp == e) {
            *pp = e->hnext;
            return;
        }
        pp = &(*pp)->hnext;
    }
}

static void cache_remove(cache_t *c, cache_entry_t *e)
{
    hash_unlink(c, e);
    lru_unlink(c, e);
    c->size -= e->size;
    c->count--;
    entry_free(e);
}

static void evict_to_fit(cache_t *c, size_t incoming)
{
    while (c->size + incoming > c->capacity && c->lru_tail) {
        cache_entry_t *victim = c->lru_tail;
        /* keep an entry that is being revalidated; step past it */
        while (victim && victim->revalidating)
            victim = victim->lru_prev;
        if (!victim)
            break;
        c->evictions++;
        cache_remove(c, victim);
    }
}

static cache_entry_t *lookup(cache_t *c, const char *key, uint64_t h)
{
    for (cache_entry_t *e = c->buckets[h % (uint64_t)c->nbuckets]; e; e = e->hnext)
        if (e->hash == h && strcmp(e->key, key) == 0)
            return e;
    return NULL;
}

cache_entry_t *cache_get(cache_t *c, const char *key)
{
    uint64_t h = hash64(key, strlen(key));
    cache_entry_t *e = lookup(c, key, h);
    if (e) {
        lru_unlink(c, e);
        lru_push_front(c, e);
    }
    return e;
}

void cache_touch_stats(cache_t *c, int hit)
{
    if (hit)
        c->hits++;
    else
        c->misses++;
}

double cache_entry_age(const cache_entry_t *e, double now)
{
    double age = now - e->stored_at;
    return age < 0 ? 0 : age;
}

/* 0 fresh, 1 stale-but-serveable (within swr), 2 stale */
int cache_entry_state(const cache_entry_t *e, double now)
{
    double age = cache_entry_age(e, now);
    if (age <= e->ttl)
        return 0;
    if (age <= e->ttl + e->swr)
        return 1;
    return 2;
}

int cache_entry_status(const cache_entry_t *e) { return e->status; }
const char *cache_entry_reason(const cache_entry_t *e) { return e->reason; }
const char *cache_entry_body(const cache_entry_t *e, size_t *len) { *len = e->body_len; return e->body; }
const char *cache_entry_etag(const cache_entry_t *e) { return e->etag; }
const char *cache_entry_last_modified(const cache_entry_t *e) { return e->last_modified; }
int cache_entry_nhdr(const cache_entry_t *e) { return e->nhdr; }
const char *cache_entry_hdr_name(const cache_entry_t *e, int i) { return e->hdrs[i].name; }
const char *cache_entry_hdr_value(const cache_entry_t *e, int i) { return e->hdrs[i].value; }
const char *cache_entry_vary(const cache_entry_t *e) { return e->vary; }
const char *cache_entry_vary_val(const cache_entry_t *e) { return e->vary_val; }
void cache_entry_set_revalidating(cache_entry_t *e, int v) { e->revalidating = v; }

/* Refresh freshness on a 304 (the stored body is still valid). */
void cache_entry_refresh(cache_t *c, cache_entry_t *e, double now, double ttl, double swr)
{
    (void)c;
    e->stored_at = now;
    e->ttl = ttl;
    e->swr = swr;
    e->revalidating = 0;
    c->revalidations++;
}

void cache_store(cache_t *c, const char *key, int status, const char *reason,
                 const char *const *hdr_names, const char *const *hdr_values, int nhdr,
                 const char *body, size_t body_len,
                 double now, double ttl, double swr,
                 const char *etag, const char *last_modified, const char *vary, const char *vary_val)
{
    uint64_t h = hash64(key, strlen(key));
    cache_entry_t *old = lookup(c, key, h);
    if (old)
        cache_remove(c, old);

    size_t size = strlen(key) + body_len + 256;
    for (int i = 0; i < nhdr; i++)
        size += strlen(hdr_names[i]) + strlen(hdr_values[i]) + 2;
    if (size > c->capacity)
        return; /* never cacheable: bigger than the whole cache */
    evict_to_fit(c, size);
    if (c->size + size > c->capacity)
        return;

    cache_entry_t *e = xcalloc(1, sizeof *e);
    e->key = xstrdup(key);
    e->hash = h;
    e->status = status;
    e->reason = reason ? xstrdup(reason) : NULL;
    e->nhdr = nhdr;
    e->hdrs = xcalloc((size_t)(nhdr > 0 ? nhdr : 1), sizeof(cache_hdr_t));
    for (int i = 0; i < nhdr; i++) {
        e->hdrs[i].name = xstrdup(hdr_names[i]);
        e->hdrs[i].value = xstrdup(hdr_values[i]);
    }
    e->body = xmalloc(body_len ? body_len : 1);
    if (body_len)
        memcpy(e->body, body, body_len);
    e->body_len = body_len;
    e->stored_at = now;
    e->ttl = ttl;
    e->swr = swr;
    e->etag = etag ? xstrdup(etag) : NULL;
    e->last_modified = last_modified ? xstrdup(last_modified) : NULL;
    e->vary = vary ? xstrdup(vary) : NULL;
    e->vary_val = vary_val ? xstrdup(vary_val) : NULL;
    e->size = size;

    e->hnext = c->buckets[h % (uint64_t)c->nbuckets];
    c->buckets[h % (uint64_t)c->nbuckets] = e;
    lru_push_front(c, e);
    c->size += size;
    c->count++;
    c->stores++;
}

void cache_stats(cache_t *c, uint64_t *hits, uint64_t *misses, uint64_t *stores, uint64_t *evictions,
                 int *count, size_t *bytes, size_t *capacity)
{
    if (hits) *hits = c->hits;
    if (misses) *misses = c->misses;
    if (stores) *stores = c->stores;
    if (evictions) *evictions = c->evictions;
    if (count) *count = c->count;
    if (bytes) *bytes = c->size;
    if (capacity) *capacity = c->capacity;
}

int cache_purge(cache_t *c, const char *key)
{
    uint64_t h = hash64(key, strlen(key));
    cache_entry_t *e = lookup(c, key, h);
    if (!e || e->revalidating)
        return 0;
    cache_remove(c, e);
    return 1;
}

void cache_clear(cache_t *c)
{
    cache_entry_t *e = c->lru_head;
    while (e) {
        cache_entry_t *n = e->lru_next;
        if (!e->revalidating)
            cache_remove(c, e); /* unlinks e; n stays valid */
        e = n;
    }
}

void cache_free(cache_t *c)
{
    if (!c)
        return;
    cache_entry_t *e = c->lru_head;
    while (e) {
        cache_entry_t *n = e->lru_next;
        entry_free(e);
        e = n;
    }
    free(c->buckets);
    free(c);
}
