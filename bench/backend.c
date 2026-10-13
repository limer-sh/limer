/*
 * backend.c - minimal epoll HTTP/1.1 backend for benchmarking Limer.
 * Answers every request with a small fixed body; consumes POST bodies.
 *   cc -O2 -o bench/backend bench/backend.c && ./bench/backend 9001
 */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

static const char RESP[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: keep-alive\r\n\r\nhello world!\n";

typedef struct { int fd; char buf[65536]; size_t len; } conn_t;

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 9001;
    int ls = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(ls, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((unsigned short)port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(ls, 4096) < 0) { perror("bind"); return 1; }
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = NULL };
    epoll_ctl(ep, EPOLL_CTL_ADD, ls, &ev);
    struct epoll_event evs[256];
    for (;;) {
        int n = epoll_wait(ep, evs, 256, -1);
        for (int i = 0; i < n; i++) {
            if (!evs[i].data.ptr) {
                for (;;) {
                    int fd = accept4(ls, NULL, NULL, SOCK_NONBLOCK);
                    if (fd < 0) break;
                    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
                    conn_t *c = calloc(1, sizeof *c);
                    c->fd = fd;
                    struct epoll_event ce = { .events = EPOLLIN, .data.ptr = c };
                    epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ce);
                }
                continue;
            }
            conn_t *c = evs[i].data.ptr;
            ssize_t r = read(c->fd, c->buf + c->len, sizeof c->buf - c->len - 1);
            if (r <= 0) { if (r < 0 && errno == EAGAIN) continue; close(c->fd); free(c); continue; }
            c->len += (size_t)r;
            c->buf[c->len] = 0;
            /* answer every complete request in the buffer */
            for (;;) {
                char *end = strstr(c->buf, "\r\n\r\n");
                if (!end) break;
                size_t hl = (size_t)(end - c->buf) + 4;
                size_t cl = 0;
                char *clh = strcasestr(c->buf, "content-length:");
                if (clh && clh < end) cl = strtoul(clh + 15, NULL, 10);
                if (c->len < hl + cl) break;
                if (write(c->fd, RESP, sizeof RESP - 1) < 0) { close(c->fd); free(c); c = NULL; break; }
                memmove(c->buf, c->buf + hl + cl, c->len - hl - cl);
                c->len -= hl + cl;
                c->buf[c->len] = 0;
            }
        }
    }
}
