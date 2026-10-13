/*
 * resolver.c - DNS lookups for dynamic upstreams.
 *
 * Lookups block, so a worker runs them on one helper thread: jobs are queued,
 * resolved in order, and finished jobs are handed back through a pipe that the
 * event loop watches. A/AAAA lookups go through getaddrinfo (so /etc/hosts and
 * the system resolver configuration apply) unless `resolvers` names servers,
 * in which case every query, SRV included, is sent to those with libresolv.
 */
#include "limer.h"
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pthread_t g_thread;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static resolve_job_t *g_queue, *g_queue_tail;
static resolve_job_t *g_done;
static int g_pipe[2] = { -1, -1 };
static int g_running;

/* ---- lookups ---- */

static void add_result(resolve_job_t *job, const struct sockaddr *sa, socklen_t len, int port, int weight, const char *target)
{
    if (job->nres >= RESOLVE_MAX_RESULTS)
        return;
    resolve_result_t *r = &job->res[job->nres++];
    memset(r, 0, sizeof *r);
    memcpy(&r->addr, sa, len);
    r->len = len;
    r->port = port;
    r->weight = weight > 0 ? weight : 1;
    snprintf(r->target, sizeof r->target, "%s", target);
    if (r->addr.ss_family == AF_INET)
        ((struct sockaddr_in *)&r->addr)->sin_port = htons((uint16_t)port);
    else if (r->addr.ss_family == AF_INET6)
        ((struct sockaddr_in6 *)&r->addr)->sin6_port = htons((uint16_t)port);
}

/* a resolver state pointed at the configured servers (IPv4 addresses) */
static int custom_state(const resolve_job_t *job, struct __res_state *st)
{
    memset(st, 0, sizeof *st);
    if (res_ninit(st) != 0)
        return -1;
    int n = 0;
    for (int i = 0; i < job->nresolvers && n < MAXNS; i++) {
        char host[64];
        int port = 53;
        snprintf(host, sizeof host, "%s", job->resolvers[i]);
        char *colon = strrchr(host, ':');
        if (colon && !strchr(host, ']') && strchr(host, ':') == colon) {
            *colon = 0;
            port = atoi(colon + 1);
        }
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof sin);
        sin.sin_family = AF_INET;
        sin.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, host, &sin.sin_addr) != 1)
            continue;
        st->nsaddr_list[n++] = sin;
    }
    if (n == 0) {
        res_nclose(st);
        return -1;
    }
    st->nscount = n;
    st->retrans = 2;
    st->retry = 2;
    st->options |= RES_RECURSE;
    return 0;
}

/* addresses of `name` via the configured servers; returns the number added */
static int query_addrs(resolve_job_t *job, struct __res_state *st, const char *name, int port, int weight)
{
    int added = 0;
    const int types[2] = { ns_t_a, ns_t_aaaa };
    for (int t = 0; t < 2; t++) {
        unsigned char answer[4096];
        int len = res_nquery(st, name, ns_c_in, types[t], answer, sizeof answer);
        if (len <= 0)
            continue;
        ns_msg msg;
        if (ns_initparse(answer, len, &msg) != 0)
            continue;
        int count = ns_msg_count(msg, ns_s_an);
        for (int i = 0; i < count; i++) {
            ns_rr rr;
            if (ns_parserr(&msg, ns_s_an, i, &rr) != 0)
                continue;
            if (ns_rr_type(rr) == ns_t_a && ns_rr_rdlen(rr) == 4) {
                struct sockaddr_in sin;
                memset(&sin, 0, sizeof sin);
                sin.sin_family = AF_INET;
                memcpy(&sin.sin_addr, ns_rr_rdata(rr), 4);
                add_result(job, (struct sockaddr *)&sin, sizeof sin, port, weight, name);
                added++;
            } else if (ns_rr_type(rr) == ns_t_aaaa && ns_rr_rdlen(rr) == 16) {
                struct sockaddr_in6 sin6;
                memset(&sin6, 0, sizeof sin6);
                sin6.sin6_family = AF_INET6;
                memcpy(&sin6.sin6_addr, ns_rr_rdata(rr), 16);
                add_result(job, (struct sockaddr *)&sin6, sizeof sin6, port, weight, name);
                added++;
            }
        }
    }
    return added;
}

static int system_addrs(resolve_job_t *job, const char *name, int port, int weight)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    int rc = getaddrinfo(name, portstr, &hints, &res);
    if (rc != 0) {
        snprintf(job->err, sizeof job->err, "%s: %s", name, gai_strerror(rc));
        return -1;
    }
    int added = 0;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
            continue;
        /* skip duplicates (getaddrinfo repeats addresses per socktype) */
        int dup = 0;
        for (int i = 0; i < job->nres && !dup; i++)
            if (job->res[i].len == ai->ai_addrlen && memcmp(&job->res[i].addr, ai->ai_addr, ai->ai_addrlen) == 0)
                dup = 1;
        if (dup)
            continue;
        add_result(job, ai->ai_addr, ai->ai_addrlen, port, weight, name);
        added++;
    }
    freeaddrinfo(res);
    return added;
}

static void lookup_addr(resolve_job_t *job)
{
    if (job->nresolvers) {
        struct __res_state st;
        if (custom_state(job, &st) < 0) {
            snprintf(job->err, sizeof job->err, "no usable resolver address");
            return;
        }
        if (query_addrs(job, &st, job->name, job->port, 1) == 0)
            snprintf(job->err, sizeof job->err, "%s: no address records", job->name);
        res_nclose(&st);
        return;
    }
    system_addrs(job, job->name, job->port, 1);
}

static void lookup_srv(resolve_job_t *job)
{
    struct __res_state st;
    int custom = job->nresolvers > 0;
    if (custom) {
        if (custom_state(job, &st) < 0) {
            snprintf(job->err, sizeof job->err, "no usable resolver address");
            return;
        }
    } else {
        memset(&st, 0, sizeof st);
        if (res_ninit(&st) != 0) {
            snprintf(job->err, sizeof job->err, "resolver init failed");
            return;
        }
    }
    unsigned char answer[8192];
    int len = res_nquery(&st, job->name, ns_c_in, ns_t_srv, answer, sizeof answer);
    if (len <= 0) {
        snprintf(job->err, sizeof job->err, "%s: SRV lookup failed (%s)", job->name, hstrerror(st.res_h_errno));
        res_nclose(&st);
        return;
    }
    ns_msg msg;
    if (ns_initparse(answer, len, &msg) != 0) {
        snprintf(job->err, sizeof job->err, "%s: cannot parse SRV answer", job->name);
        res_nclose(&st);
        return;
    }
    int count = ns_msg_count(msg, ns_s_an);
    int targets = 0;
    for (int i = 0; i < count; i++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, i, &rr) != 0 || ns_rr_type(rr) != ns_t_srv || ns_rr_rdlen(rr) < 7)
            continue;
        const unsigned char *rd = ns_rr_rdata(rr);
        int weight = (rd[2] << 8) | rd[3];
        int port = (rd[4] << 8) | rd[5];
        char target[NS_MAXDNAME];
        if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rd + 6, target, sizeof target) < 0)
            continue;
        if (target[0] == 0 || strcmp(target, ".") == 0)
            continue; /* "service not available" record */
        targets++;
        /* the additional section may carry the target's addresses; look it up regardless */
        if (custom)
            query_addrs(job, &st, target, port, weight);
        else
            system_addrs(job, target, port, weight);
    }
    if (targets == 0)
        snprintf(job->err, sizeof job->err, "%s: no SRV records", job->name);
    else if (job->nres == 0)
        snprintf(job->err, sizeof job->err, "%s: SRV targets have no addresses", job->name);
    res_nclose(&st);
}

void resolve_sync(resolve_job_t *job)
{
    job->nres = 0;
    job->err[0] = 0;
    if (job->kind == RESOLVE_SRV)
        lookup_srv(job);
    else
        lookup_addr(job);
}

/* ---- the helper thread ---- */

static void *resolver_main(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&g_mu);
    while (g_running) {
        while (g_running && !g_queue)
            pthread_cond_wait(&g_cv, &g_mu);
        if (!g_running)
            break;
        resolve_job_t *job = g_queue;
        g_queue = job->next;
        if (!g_queue)
            g_queue_tail = NULL;
        pthread_mutex_unlock(&g_mu);
        job->next = NULL;
        resolve_sync(job);
        pthread_mutex_lock(&g_mu);
        job->next = g_done;
        g_done = job;
        (void)!write(g_pipe[1], "r", 1);
    }
    pthread_mutex_unlock(&g_mu);
    return NULL;
}

int resolver_start(void)
{
    if (g_running)
        return g_pipe[0];
    if (pipe(g_pipe) < 0)
        return -1;
    for (int i = 0; i < 2; i++) {
        fcntl(g_pipe[i], F_SETFL, fcntl(g_pipe[i], F_GETFL) | O_NONBLOCK);
        fcntl(g_pipe[i], F_SETFD, FD_CLOEXEC);
    }
    g_running = 1;
    if (pthread_create(&g_thread, NULL, resolver_main, NULL) != 0) {
        g_running = 0;
        close(g_pipe[0]);
        close(g_pipe[1]);
        g_pipe[0] = g_pipe[1] = -1;
        return -1;
    }
    return g_pipe[0];
}

void resolver_submit(resolve_job_t *job)
{
    job->next = NULL;
    pthread_mutex_lock(&g_mu);
    if (g_queue_tail)
        g_queue_tail->next = job;
    else
        g_queue = job;
    g_queue_tail = job;
    pthread_cond_signal(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

resolve_job_t *resolver_take_done(void)
{
    char drain[64];
    while (read(g_pipe[0], drain, sizeof drain) > 0)
        ;
    pthread_mutex_lock(&g_mu);
    resolve_job_t *list = g_done;
    g_done = NULL;
    pthread_mutex_unlock(&g_mu);
    /* the done list is newest-first: reverse it so results apply in order */
    resolve_job_t *out = NULL;
    while (list) {
        resolve_job_t *n = list->next;
        list->next = out;
        out = list;
        list = n;
    }
    return out;
}

void resolver_stop(void)
{
    if (!g_running)
        return;
    pthread_mutex_lock(&g_mu);
    g_running = 0;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
    pthread_join(g_thread, NULL);
    close(g_pipe[0]);
    close(g_pipe[1]);
    g_pipe[0] = g_pipe[1] = -1;
}
