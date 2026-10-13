/* util.c - small helpers: time, memory, parsing, hashing, sockets */
#include "limer.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

double now_mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

double now_wall(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void oom(void)
{
    fputs("limer: out of memory\n", stderr);
    abort();
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        oom();
    return p;
}

void *xcalloc(size_t n, size_t m)
{
    void *p = calloc(n ? n : 1, m ? m : 1);
    if (!p)
        oom();
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q)
        oom();
    return q;
}

char *xstrdup(const char *s)
{
    if (!s)
        return NULL;
    char *d = strdup(s);
    if (!d)
        oom();
    return d;
}

char *xstrndup(const char *s, size_t n)
{
    char *d = xmalloc(n + 1);
    memcpy(d, s, n);
    d[n] = 0;
    return d;
}

int strcaseeq(const char *a, const char *b)
{
    return a && b && strcasecmp(a, b) == 0;
}

int str_has_prefix(const char *s, const char *p)
{
    return strncmp(s, p, strlen(p)) == 0;
}

/* "30s", "2m", "500ms", "1h", "1.5s", "0" */
int parse_duration(const char *s, double *out)
{
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    if (end == s || errno)
        return -1;
    if (*end == 0) {
        *out = v; /* bare number means seconds */
        return 0;
    }
    if (strcmp(end, "ms") == 0)
        v /= 1000.0;
    else if (strcmp(end, "s") == 0)
        ;
    else if (strcmp(end, "m") == 0)
        v *= 60.0;
    else if (strcmp(end, "h") == 0)
        v *= 3600.0;
    else if (strcmp(end, "d") == 0)
        v *= 86400.0;
    else
        return -1;
    if (v < 0)
        return -1;
    *out = v;
    return 0;
}

/* "8m", "512k", "1g", "100", "4mb", "2MiB" */
int parse_size(const char *s, size_t *out)
{
    char *end;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (end == s || errno)
        return -1;
    char u = (char)tolower((unsigned char)*end);
    unsigned long long mult = 1;
    if (u == 0)
        mult = 1;
    else if (u == 'k')
        mult = 1024ULL;
    else if (u == 'm')
        mult = 1024ULL * 1024;
    else if (u == 'g')
        mult = 1024ULL * 1024 * 1024;
    else
        return -1;
    if (u) {
        end++;
        if (*end && !(strcaseeq(end, "b") || strcaseeq(end, "ib")))
            return -1;
    }
    *out = (size_t)(v * mult);
    return 0;
}

/* FNV-1a 64-bit with a final avalanche mix. */
uint64_t hash64_seed(const void *data, size_t len, uint64_t seed)
{
    const unsigned char *p = data;
    uint64_t h = 0xcbf29ce484222325ULL ^ seed;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

uint64_t hash64(const void *data, size_t len)
{
    return hash64_seed(data, len, 0);
}

int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0)
        return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int set_cloexec(int fd)
{
    int fl = fcntl(fd, F_GETFD, 0);
    if (fl < 0)
        return -1;
    return fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
}

/*
 * Accepts "host:port", ":port", "[v6]:port", "host" (default port),
 * optionally prefixed with "http://". Returns 0 on success.
 */
int parse_hostport(const char *s, char **host, int *port, int default_port)
{
    if (str_has_prefix(s, "http://"))
        s += 7;
    size_t n = strlen(s);
    while (n && s[n - 1] == '/')
        n--;
    const char *colon = NULL;
    const char *hstart = s, *hend;
    if (n && s[0] == '[') {
        const char *rb = memchr(s, ']', n);
        if (!rb)
            return -1;
        hstart = s + 1;
        hend = rb;
        if ((size_t)(rb + 1 - s) < n) {
            if (rb[1] != ':')
                return -1;
            colon = rb + 1;
        }
    } else {
        const char *c = memrchr(s, ':', n);
        /* bare IPv6 without brackets is ambiguous; treat multiple colons as host */
        if (c && memchr(s, ':', n) == c)
            colon = c;
        hend = colon ? colon : s + n;
    }
    int p = default_port;
    if (colon) {
        char *end;
        long v = strtol(colon + 1, &end, 10);
        if (end == colon + 1 || (size_t)(end - s) != n || v < 0 || v > 65535)
            return -1;
        p = (int)v;
    }
    if (p <= 0)
        return -1;
    *host = xstrndup(hstart, (size_t)(hend - hstart));
    *port = p;
    return 0;
}

void sockaddr_to_str(const struct sockaddr *sa, char *out, size_t outlen, int with_port)
{
    char ip[INET6_ADDRSTRLEN] = "?";
    int port = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof ip);
        port = ntohs(in->sin_port);
        if (with_port)
            snprintf(out, outlen, "%s:%d", ip, port);
        else
            snprintf(out, outlen, "%s", ip);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
        /* render v4-mapped addresses as plain IPv4 */
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            struct in_addr a4;
            memcpy(&a4, &in6->sin6_addr.s6_addr[12], 4);
            inet_ntop(AF_INET, &a4, ip, sizeof ip);
            port = ntohs(in6->sin6_port);
            if (with_port)
                snprintf(out, outlen, "%s:%d", ip, port);
            else
                snprintf(out, outlen, "%s", ip);
            return;
        }
        inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof ip);
        port = ntohs(in6->sin6_port);
        if (with_port)
            snprintf(out, outlen, "[%s]:%d", ip, port);
        else
            snprintf(out, outlen, "%s", ip);
    } else {
        snprintf(out, outlen, "unknown");
    }
}

/* Match "10.0.0.0/8", "192.168.1.5", "fd00::/8" against an address. */
int cidr_match(const char *cidr, const struct sockaddr *addr)
{
    char ipstr[INET6_ADDRSTRLEN + 8];
    snprintf(ipstr, sizeof ipstr, "%s", cidr);
    int bits = -1;
    char *slash = strchr(ipstr, '/');
    if (slash) {
        *slash = 0;
        bits = atoi(slash + 1);
    }
    unsigned char want[16], have[16];
    int family = strchr(ipstr, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(family, ipstr, want) != 1)
        return 0;
    int hlen;
    if (addr->sa_family == AF_INET) {
        memcpy(have, &((const struct sockaddr_in *)addr)->sin_addr, 4);
        hlen = 4;
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            memcpy(have, &in6->sin6_addr.s6_addr[12], 4);
            hlen = 4;
        } else {
            memcpy(have, &in6->sin6_addr, 16);
            hlen = 16;
        }
    } else {
        return 0;
    }
    int wlen = family == AF_INET ? 4 : 16;
    if (wlen != hlen)
        return 0;
    if (bits < 0 || bits > wlen * 8)
        bits = wlen * 8;
    int full = bits / 8, rem = bits % 8;
    if (memcmp(want, have, (size_t)full) != 0)
        return 0;
    if (rem) {
        unsigned char mask = (unsigned char)(0xff << (8 - rem));
        if ((want[full] & mask) != (have[full] & mask))
            return 0;
    }
    return 1;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Percent-decode (and '+' -> space). Returns output length or -1 if too long. */
int url_decode(const char *in, size_t inlen, char *out, size_t outlen)
{
    size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        if (o + 1 >= outlen)
            return -1;
        char c = in[i];
        if (c == '+') {
            out[o++] = ' ';
        } else if (c == '%' && i + 2 < inlen) {
            int h = hexval((unsigned char)in[i + 1]);
            int l = hexval((unsigned char)in[i + 2]);
            if (h >= 0 && l >= 0) {
                out[o++] = (char)((h << 4) | l);
                i += 2;
            } else {
                out[o++] = c;
            }
        } else {
            out[o++] = c;
        }
    }
    out[o] = 0;
    return (int)o;
}

int is_numeric(const char *s, double *out)
{
    if (!s || !*s)
        return 0;
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    if (errno || *end != 0 || isnan(v))
        return 0;
    if (out)
        *out = v;
    return 1;
}

/* Simple glob: '*' matches any sequence (including '/'), '?' one char. */
int glob_match(const char *p, const char *s)
{
    const char *star = NULL, *ss = NULL;
    while (*s) {
        if (*p == '*') {
            star = p++;
            ss = s;
        } else if (*p == '?' || *p == *s) {
            p++;
            s++;
        } else if (star) {
            p = star + 1;
            s = ++ss;
        } else {
            return 0;
        }
    }
    while (*p == '*')
        p++;
    return *p == 0;
}
