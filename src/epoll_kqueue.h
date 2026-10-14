/*
 * epoll_kqueue.h - the subset of epoll and timerfd that proxy.c uses, on kqueue
 * (macOS and the BSDs). Linux uses the real thing.
 *
 * Level-triggered, like limer's epoll use: EPOLLIN maps to EVFILT_READ and
 * EPOLLOUT to EVFILT_WRITE. kqueue reports the two filters as separate events,
 * so epoll_wait() merges them back into one event per registration, and the
 * loop calls each object once per batch, as it does on Linux.
 *
 * EPOLLRDHUP on its own (no EPOLLIN) registers no read filter: kqueue cannot
 * report "peer closed" without also reporting pending data, and limer asks for
 * RDHUP alone exactly when it is applying backpressure and must not be woken
 * for data. A hangup is then seen when reading resumes.
 *
 * A timerfd is a kqueue of its own carrying one EVFILT_TIMER; the outer kqueue
 * sees it readable when the timer fires, and timerfd_drain() consumes it.
 */
#ifndef LIMER_EPOLL_KQUEUE_H
#define LIMER_EPOLL_KQUEUE_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define EPOLLIN      0x001u
#define EPOLLOUT     0x004u
#define EPOLLERR     0x008u
#define EPOLLHUP     0x010u
#define EPOLLRDHUP   0x2000u
#define EPOLL_CLOEXEC 1
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef union epoll_data {
    void    *ptr;
    int      fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t     events;
    epoll_data_t data;
};

/* the mask registered per descriptor, to know which filters to add or drop */
static uint32_t *g_kq_masks;
static int       g_kq_nmasks;

static int kq_remember(int fd, uint32_t mask)
{
    if (fd >= g_kq_nmasks) {
        int n = g_kq_nmasks ? g_kq_nmasks : 1024;
        while (n <= fd)
            n *= 2;
        uint32_t *m = realloc(g_kq_masks, sizeof(uint32_t) * (size_t)n);
        if (!m)
            return -1;
        memset(m + g_kq_nmasks, 0, sizeof(uint32_t) * (size_t)(n - g_kq_nmasks));
        g_kq_masks = m;
        g_kq_nmasks = n;
    }
    g_kq_masks[fd] = mask;
    return 0;
}

static int epoll_create1(int flags)
{
    int kq = kqueue();
    if (kq >= 0 && (flags & EPOLL_CLOEXEC))
        fcntl(kq, F_SETFD, FD_CLOEXEC);
    return kq;
}

static int epoll_ctl(int kq, int op, int fd, struct epoll_event *ev)
{
    uint32_t old = fd < g_kq_nmasks ? g_kq_masks[fd] : 0;
    uint32_t want = op == EPOLL_CTL_DEL ? 0 : ev->events;
    void *udata = op == EPOLL_CTL_DEL ? NULL : ev->data.ptr;
    struct kevent ch[2];
    int n = 0;
    int rd_old = (old & EPOLLIN) != 0, rd_new = (want & EPOLLIN) != 0;
    int wr_old = (old & EPOLLOUT) != 0, wr_new = (want & EPOLLOUT) != 0;
    if (op == EPOLL_CTL_ADD)
        rd_old = wr_old = 0;   /* a reused descriptor: the old filters went with its close() */
    if (rd_new)
        EV_SET(&ch[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, udata);
    else if (rd_old)
        EV_SET(&ch[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    if (wr_new)
        EV_SET(&ch[n++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, udata);
    else if (wr_old)
        EV_SET(&ch[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    if (kq_remember(fd, want) < 0) {
        errno = ENOMEM;
        return -1;
    }
    for (int i = 0; i < n; i++) {
        /* one change at a time, so a failed delete (already gone) does not stop the rest */
        if (kevent(kq, &ch[i], 1, NULL, 0, NULL) < 0 && !(ch[i].flags & EV_DELETE))
            return -1;
    }
    return 0;
}

static int epoll_wait(int kq, struct epoll_event *out, int max, int timeout_ms)
{
    struct kevent kev[512];
    int cap = max * 2 < 512 ? max * 2 : 512;
    struct timespec ts, *tsp = NULL;
    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        tsp = &ts;
    }
    int n = kevent(kq, NULL, 0, kev, cap, tsp);
    if (n <= 0)
        return n;
    int m = 0;
    for (int i = 0; i < n; i++) {
        uint32_t ev = 0;
        if (kev[i].flags & EV_ERROR) {
            ev |= EPOLLERR;
        } else if (kev[i].filter == EVFILT_READ) {
            ev |= EPOLLIN;
            if (kev[i].flags & EV_EOF)
                ev |= EPOLLRDHUP | (kev[i].fflags ? EPOLLERR : 0);
        } else if (kev[i].filter == EVFILT_WRITE) {
            ev |= EPOLLOUT;
            if (kev[i].flags & EV_EOF)
                ev |= EPOLLHUP | (kev[i].fflags ? EPOLLERR : 0);
        }
        int j = 0;
        while (j < m && out[j].data.ptr != kev[i].udata)
            j++;
        if (j == m) {
            if (m == max)
                continue;     /* more than max registrations ready: the rest stay pending */
            out[m].data.ptr = kev[i].udata;
            out[m].events = 0;
            m++;
        }
        out[j].events |= ev;
    }
    return m;
}

/* timerfd on a private kqueue */
#define TFD_NONBLOCK 1
#define TFD_CLOEXEC  2
struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

static int timerfd_create(int clock, int flags)
{
    (void)clock;
    int kq = kqueue();
    if (kq >= 0 && (flags & TFD_CLOEXEC))
        fcntl(kq, F_SETFD, FD_CLOEXEC);
    return kq;
}

static int timerfd_settime(int fd, int flags, const struct itimerspec *its, struct itimerspec *old)
{
    (void)flags;
    (void)old;
    long ms = (long)its->it_interval.tv_sec * 1000 + its->it_interval.tv_nsec / 1000000L;
    if (ms <= 0)
        ms = 1;
    struct kevent ch;
    EV_SET(&ch, 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, ms, NULL);
    return kevent(fd, &ch, 1, NULL, 0, NULL);
}

/* Consume a fired timer so the timerfd stops being readable. */
static void timerfd_drain(int fd)
{
    struct kevent got[4];
    struct timespec zero = { 0, 0 };
    while (kevent(fd, NULL, 0, got, 4, &zero) > 0)
        ;
}

#endif
