/*
 * registry.c - self-registration service discovery.
 *
 * A fixed, lock-free table that lives in a MAP_SHARED region the master creates
 * before it forks, so every worker shares one live set. Backends announce
 * themselves with POST /register (and heartbeat by repeating it) and leave with
 * POST /deregister; an entry whose heartbeat stops is evicted when its TTL
 * passes. A pool configured with `discover <name>` draws its members from the
 * entries registered under that name.
 *
 * Lock-free: each slot has an atomic `state` (free/live). A writer fills a free
 * slot's fields, then publishes state=live with a release store; a reader loads
 * state with acquire before trusting the fields. `gen` is bumped whenever
 * membership changes (a new entry, a dropped entry, a weight change) so a worker
 * can tell in O(1) whether it must rebuild its pools. A single backend sends one
 * request at a time, so two writers never race on the same (pool,address).
 */
#include "limer.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define REG_MAGIC 0x4c494d5245473031ULL  /* "LIMREG01" */

enum { REG_FREE = 0, REG_LIVE = 1 };

size_t registry_bytes(void)
{
    return sizeof(registry_t);
}

void registry_reset(registry_t *r)
{
    if (!r)
        return;
    memset(r, 0, sizeof *r);
    r->magic = REG_MAGIC;
}

/* "ip:port" for a resolved address; [v6]:port for IPv6. */
static void addr_text(const struct sockaddr *sa, char *out, size_t outlen)
{
    char ip[INET6_ADDRSTRLEN] = "?";
    int port = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &s->sin_addr, ip, sizeof ip);
        port = ntohs(s->sin_port);
        snprintf(out, outlen, "%s:%d", ip, port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof ip);
        port = ntohs(s->sin6_port);
        snprintf(out, outlen, "[%s]:%d", ip, port);
    } else {
        snprintf(out, outlen, "?");
    }
}

/* host part of a slot's "ip:port" (without the port), into out. */
static void slot_ip(const reg_slot_t *sl, char *out, size_t outlen)
{
    const char *a = sl->addr;
    if (*a == '[') {
        const char *e = strchr(a, ']');
        size_t n = e ? (size_t)(e - a - 1) : 0;
        if (n >= outlen)
            n = outlen - 1;
        memcpy(out, a + 1, n);
        out[n] = 0;
    } else {
        const char *colon = strrchr(a, ':');
        size_t n = colon ? (size_t)(colon - a) : strlen(a);
        if (n >= outlen)
            n = outlen - 1;
        memcpy(out, a, n);
        out[n] = 0;
    }
}

static int slot_port(const reg_slot_t *sl)
{
    if (sl->sa.ss_family == AF_INET)
        return ntohs(((const struct sockaddr_in *)&sl->sa)->sin_port);
    if (sl->sa.ss_family == AF_INET6)
        return ntohs(((const struct sockaddr_in6 *)&sl->sa)->sin6_port);
    return 0;
}

uint64_t registry_gen(const registry_t *r)
{
    return r ? __atomic_load_n(&r->gen, __ATOMIC_RELAXED) : 0;
}

int registry_put(registry_t *r, const char *pool, const struct sockaddr *sa, socklen_t salen, int weight, double expires)
{
    if (!r || !pool || !sa || salen > sizeof(struct sockaddr_storage))
        return -1;
    char text[REG_ADDR_LEN];
    addr_text(sa, text, sizeof text);
    if (weight < 1)
        weight = 1;
    /* refresh an existing registration (a heartbeat) */
    int free_idx = -1;
    for (int i = 0; i < REG_MAX_SLOTS; i++) {
        reg_slot_t *sl = &r->slots[i];
        if (__atomic_load_n(&sl->state, __ATOMIC_ACQUIRE) != REG_LIVE) {
            if (free_idx < 0)
                free_idx = i;
            continue;
        }
        if (strcmp(sl->pool, pool) == 0 && strcmp(sl->addr, text) == 0) {
            sl->expires = expires;   /* aligned 8-byte store; membership is what the atomics guard */
            if (sl->weight != weight) {
                sl->weight = weight;
                __atomic_add_fetch(&r->gen, 1, __ATOMIC_RELAXED);
                return 1;
            }
            return 0;   /* plain heartbeat, membership unchanged */
        }
    }
    if (free_idx < 0)
        return -1;      /* table full */
    /* bound how many entries one source address can hold, so a single authorized
     * (but misbehaving) host cannot fill the table by registering many ports */
    char newip[INET6_ADDRSTRLEN];
    reg_slot_t probe = { 0 };
    snprintf(probe.addr, sizeof probe.addr, "%s", text);
    slot_ip(&probe, newip, sizeof newip);
    int same_ip = 0;
    for (int i = 0; i < REG_MAX_SLOTS; i++) {
        reg_slot_t *s = &r->slots[i];
        if (__atomic_load_n(&s->state, __ATOMIC_ACQUIRE) != REG_LIVE)
            continue;
        char sip[INET6_ADDRSTRLEN];
        slot_ip(s, sip, sizeof sip);
        if (strcmp(sip, newip) == 0 && ++same_ip >= REG_MAX_PER_IP)
            return -1;
    }
    reg_slot_t *sl = &r->slots[free_idx];
    snprintf(sl->pool, sizeof sl->pool, "%s", pool);
    snprintf(sl->addr, sizeof sl->addr, "%s", text);
    memset(&sl->sa, 0, sizeof sl->sa);
    memcpy(&sl->sa, sa, salen);
    sl->salen = salen;
    sl->weight = weight;
    sl->expires = expires;
    __atomic_store_n(&sl->state, REG_LIVE, __ATOMIC_RELEASE);
    __atomic_add_fetch(&r->gen, 1, __ATOMIC_RELAXED);
    return 1;
}

int registry_del(registry_t *r, const char *pool, const char *ip, int port)
{
    if (!r || !ip)
        return 0;
    int removed = 0;
    for (int i = 0; i < REG_MAX_SLOTS; i++) {
        reg_slot_t *sl = &r->slots[i];
        if (__atomic_load_n(&sl->state, __ATOMIC_ACQUIRE) != REG_LIVE)
            continue;
        if (pool && *pool && strcmp(sl->pool, pool) != 0)
            continue;
        char sip[INET6_ADDRSTRLEN];
        slot_ip(sl, sip, sizeof sip);
        if (strcmp(sip, ip) != 0)
            continue;
        if (port && slot_port(sl) != port)
            continue;
        __atomic_store_n(&sl->state, REG_FREE, __ATOMIC_RELEASE);
        __atomic_add_fetch(&r->gen, 1, __ATOMIC_RELAXED);
        removed++;
    }
    return removed;
}

int registry_evict(registry_t *r, double now)
{
    if (!r)
        return 0;
    int removed = 0;
    for (int i = 0; i < REG_MAX_SLOTS; i++) {
        reg_slot_t *sl = &r->slots[i];
        if (__atomic_load_n(&sl->state, __ATOMIC_ACQUIRE) != REG_LIVE)
            continue;
        double exp = sl->expires;
        if (exp > 0 && exp < now) {
            __atomic_store_n(&sl->state, REG_FREE, __ATOMIC_RELEASE);
            __atomic_add_fetch(&r->gen, 1, __ATOMIC_RELAXED);
            removed++;
        }
    }
    return removed;
}

int registry_live(const registry_t *r, const char *pool, double now)
{
    if (!r)
        return 0;
    int n = 0;
    for (int i = 0; i < REG_MAX_SLOTS; i++) {
        const reg_slot_t *sl = &r->slots[i];
        if (__atomic_load_n(&sl->state, __ATOMIC_ACQUIRE) != REG_LIVE)
            continue;
        if (pool && *pool && strcmp(sl->pool, pool) != 0)
            continue;
        if (sl->expires > 0 && sl->expires < now)
            continue;
        n++;
    }
    return n;
}

/* Persist live entries as "pool ip port weight remaining_ttl", so a restart or
 * an in-place upgrade (which re-mmaps a fresh region) starts populated. Stored
 * remaining TTL, not an absolute time, because the monotonic clock resets. */
int registry_save(const registry_t *r, const char *path, double now)
{
    if (!r || !path)
        return -1;
    char tmp[1200];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return -1;
    for (int i = 0; i < REG_MAX_SLOTS; i++) {
        const reg_slot_t *sl = &r->slots[i];
        if (__atomic_load_n(&sl->state, __ATOMIC_ACQUIRE) != REG_LIVE)
            continue;
        double remaining = sl->expires > 0 ? sl->expires - now : 0;
        if (sl->expires > 0 && remaining <= 0)
            continue;
        char ip[INET6_ADDRSTRLEN];
        slot_ip(sl, ip, sizeof ip);
        fprintf(f, "%s %s %d %d %.0f\n", sl->pool, ip, slot_port(sl), sl->weight,
                sl->expires > 0 ? remaining : 0.0);
    }
    fflush(f);
    fclose(f);
    if (rename(tmp, path) < 0)
        return -1;
    return 0;
}

int registry_load(registry_t *r, const char *path, double now)
{
    if (!r || !path)
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[512];
    int loaded = 0;
    while (fgets(line, sizeof line, f)) {
        char pool[REG_POOL_LEN], ip[INET6_ADDRSTRLEN];
        int port = 0, weight = 1;
        double remaining = 0;
        if (sscanf(line, "%63s %45s %d %d %lf", pool, ip, &port, &weight, &remaining) < 4)
            continue;
        if (port <= 0 || port > 65535)
            continue;
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof ss);
        socklen_t sl;
        if (strchr(ip, ':')) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;
            if (inet_pton(AF_INET6, ip, &s->sin6_addr) != 1)
                continue;
            s->sin6_family = AF_INET6;
            s->sin6_port = htons((uint16_t)port);
            sl = sizeof *s;
        } else {
            struct sockaddr_in *s = (struct sockaddr_in *)&ss;
            if (inet_pton(AF_INET, ip, &s->sin_addr) != 1)
                continue;
            s->sin_family = AF_INET;
            s->sin_port = htons((uint16_t)port);
            sl = sizeof *s;
        }
        double expires = remaining > 0 ? now + remaining : 0;
        if (registry_put(r, pool, (struct sockaddr *)&ss, sl, weight, expires) >= 0)
            loaded++;
    }
    fclose(f);
    return loaded;
}
