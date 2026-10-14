/*
 * compat.h - the few Linux interfaces limer.sh uses, provided on macOS.
 *
 * Linux needs nothing from this file. Elsewhere it emulates the socket()/
 * accept4() flags with fcntl() and supplies memrchr(). The event loop's epoll
 * calls are mapped onto kqueue separately, in epoll_kqueue.h.
 */
#ifndef LIMER_COMPAT_H
#define LIMER_COMPAT_H

#ifndef __linux__

#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SOCK_NONBLOCK
/* Not real socket types here: limer_socket() strips them and applies fcntl. */
#define SOCK_NONBLOCK 0x10000000
#define SOCK_CLOEXEC  0x20000000

static inline int limer_fd_flags(int fd, int flags)
{
    if ((flags & SOCK_NONBLOCK) && fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0)
        return -1;
    if ((flags & SOCK_CLOEXEC) && fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
        return -1;
    /* no MSG_NOSIGNAL here; SIGPIPE is ignored process-wide, this is belt and braces */
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    return 0;
}

static inline int limer_socket(int domain, int type, int proto)
{
    int fd = socket(domain, type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC), proto);
    if (fd >= 0 && limer_fd_flags(fd, type) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}
#define socket(d, t, p) limer_socket((d), (t), (p))

static inline int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags)
{
    int c = accept(fd, addr, len);
    if (c >= 0 && limer_fd_flags(c, flags) < 0) {
        close(c);
        return -1;
    }
    return c;
}
#endif /* SOCK_NONBLOCK */

static inline void *limer_memrchr(const void *s, int c, size_t n)
{
    const unsigned char *p = (const unsigned char *)s + n;
    while (n--)
        if (*--p == (unsigned char)c)
            return (void *)p;
    return NULL;
}
#define memrchr(s, c, n) limer_memrchr((s), (c), (n))

#endif /* !__linux__ */

/* Path of the running executable (for upgrades): fills buf, returns 0 or -1. */
int limer_exe_path(char *buf, size_t len);

#endif
