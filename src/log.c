/* log.c - leveled logging to stderr and access logging to stdout */
#include "limer.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

int log_level = LOG_INFO;

static const char *level_names[] = { "debug", "info", "warn", "error" };

void log_set_level_name(const char *name)
{
    for (int i = 0; i < 4; i++)
        if (strcaseeq(name, level_names[i])) {
            log_level = i;
            return;
        }
}

static void timestamp(char *out, size_t n)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    size_t k = strftime(out, n, "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out + k, n - k, ".%03ldZ", ts.tv_nsec / 1000000);
}

void log_msg(int level, const char *fmt, ...)
{
    char ts[40];
    char line[2048];
    timestamp(ts, sizeof ts);
    int n = snprintf(line, sizeof line, "%s %-5s [%d] ", ts, level_names[level & 3], (int)getpid());
    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(line + n, sizeof line - (size_t)n, fmt, ap);
    va_end(ap);
    if (m < 0)
        m = 0;
    size_t len = (size_t)n + (size_t)m;
    if (len >= sizeof line - 1)
        len = sizeof line - 2;
    line[len++] = '\n';
    (void)!write(STDERR_FILENO, line, len);
}

void log_access(const char *fmt, ...)
{
    char ts[40];
    char line[4096];
    timestamp(ts, sizeof ts);
    int n = snprintf(line, sizeof line, "%s ", ts);
    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(line + n, sizeof line - (size_t)n, fmt, ap);
    va_end(ap);
    if (m < 0)
        m = 0;
    size_t len = (size_t)n + (size_t)m;
    if (len >= sizeof line - 1)
        len = sizeof line - 2;
    line[len++] = '\n';
    (void)!write(STDOUT_FILENO, line, len);
}

void log_access_to(int fd, const char *line, size_t len)
{
    if (fd < 0)
        return;
    char ts[40];
    timestamp(ts, sizeof ts);
    char head[48];
    int n = snprintf(head, sizeof head, "%s ", ts);
    struct iovec iov[3] = { { head, (size_t)n }, { (void *)line, len }, { (void *)"\n", 1 } };
    (void)!writev(fd, iov, 3);
}

static const char *user_name(uid_t uid, char *out, size_t n)
{
    struct passwd *pw = getpwuid(uid);
    if (pw)
        snprintf(out, n, "%s", pw->pw_name);
    else
        snprintf(out, n, "uid %d", (int)uid);
    return out;
}

static void parent_dir(const char *path, char *out, size_t n)
{
    snprintf(out, n, "%s", path);
    char *slash = strrchr(out, '/');
    if (!slash)
        snprintf(out, n, ".");
    else if (slash == out)
        out[1] = 0;
    else
        *slash = 0;
}

int log_open_target(const char *spec, char *err, size_t errlen)
{
    if (!spec || strcaseeq(spec, "stdout"))
        return STDOUT_FILENO;
    if (strcaseeq(spec, "stderr"))
        return STDERR_FILENO;
    if (strcaseeq(spec, "off") || strcaseeq(spec, "discard") || strcaseeq(spec, "none"))
        return -1;
    const char *path = spec;
    if (str_has_prefix(path, "file "))
        path += 5;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) {
        /* Permission denied: say whose file (or directory) it is, and who limer runs as */
        int e = errno;
        struct stat st;
        char dir[1024], owner[64], me[64];
        parent_dir(path, dir, sizeof dir);
        if (e == EACCES && stat(path, &st) == 0)
            snprintf(err, errlen, "cannot open log file '%s': %s (it belongs to %s, and limer runs as %s)", path,
                     strerror(e), user_name(st.st_uid, owner, sizeof owner), user_name(geteuid(), me, sizeof me));
        else if (e == EACCES && stat(dir, &st) == 0)
            snprintf(err, errlen, "cannot create log file '%s': %s (%s belongs to %s, and limer runs as %s)", path,
                     strerror(e), dir, user_name(st.st_uid, owner, sizeof owner), user_name(geteuid(), me, sizeof me));
        else
            snprintf(err, errlen, "cannot open log file '%s': %s", path, strerror(e));
    }
    return fd;
}

int log_check_target(const char *spec, char *err, size_t errlen)
{
    if (!spec || strcaseeq(spec, "stdout") || strcaseeq(spec, "stderr") || strcaseeq(spec, "off") ||
        strcaseeq(spec, "discard") || strcaseeq(spec, "none"))
        return 0;
    const char *path = spec;
    if (str_has_prefix(path, "file "))
        path += 5;
    struct stat st, ds;
    char dir[1024], owner[64];
    parent_dir(path, dir, sizeof dir);
    if (stat(path, &st) == 0) {
        if (access(path, W_OK) < 0) {
            int e = errno;   /* before user_name(): getpwuid() may change errno */
            snprintf(err, errlen, "cannot write log file '%s': %s (it belongs to %s)", path, strerror(e),
                     user_name(st.st_uid, owner, sizeof owner));
            return -1;
        }
        /* Root can write anything, so ask whether the server could: a file of root's in a
         * directory that belongs to another user is one a server running as that user cannot write. */
        if (geteuid() == 0 && st.st_uid == 0 && S_ISREG(st.st_mode) && stat(dir, &ds) == 0 && ds.st_uid != 0) {
            user_name(ds.st_uid, owner, sizeof owner);
            snprintf(err, errlen, "log file '%s' belongs to root, but %s belongs to %s: a server running as %s cannot write it (chown %s '%s')",
                     path, dir, owner, owner, owner, path);
            return -1;
        }
        return 0;
    }
    if (errno != ENOENT) {
        snprintf(err, errlen, "cannot open log file '%s': %s", path, strerror(errno));
        return -1;
    }
    if (access(dir, W_OK) < 0) {
        snprintf(err, errlen, "cannot create log file '%s': %s: %s", path, dir, strerror(errno));
        return -1;
    }
    return 0;
}

void log_json_escape(buf_t *b, const char *s)
{
    buf_append(b, "\"", 1);
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')
            buf_printf(b, "\\%c", c);
        else if (c < 0x20)
            buf_printf(b, "\\u%04x", c);
        else
            buf_append(b, s, 1);
    }
    buf_append(b, "\"", 1);
}
