/* log.c - leveled logging to stderr and access logging to stdout */
#include "limer.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#ifdef LIMER_ENCODE
#include <zlib.h>
#endif

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

/* ------------------------------------------------------------------ */
/* Rolling access log files                                            */
/* ------------------------------------------------------------------ */

log_roll_t *log_roll_new(const char *path)
{
    log_roll_t *r = xcalloc(1, sizeof *r);
    r->path = xstrdup(path);
    r->size = 100 * 1024 * 1024;   /* Caddy's defaults: 100 MiB, 10 files, 90 days, gzipped */
    r->keep = 10;
    r->keep_for = 90 * 86400.0;
#ifdef LIMER_ENCODE
    r->gzip = 1;
#endif
    return r;
}

void log_roll_free(log_roll_t *r)
{
    if (!r)
        return;
    free(r->path);
    free(r);
}

/* "dir/access.log": "dir", "access" and ".log" (the extension from the last dot of the file
 * name; none for "access" or ".hidden"); the directory "" for a file in "/", "." for none */
static void roll_split(const char *path, char *dir, size_t dn, char *name, size_t nn, char *ext, size_t en)
{
    const char *slash = strrchr(path, '/');
    const char *file = slash ? slash + 1 : path;
    if (slash)
        snprintf(dir, dn, "%.*s", (int)(slash - path), path);
    else
        snprintf(dir, dn, ".");
    const char *dot = strrchr(file, '.');
    if (!dot || dot == file) {
        snprintf(name, nn, "%s", file);
        ext[0] = 0;
    } else {
        snprintf(name, nn, "%.*s", (int)(dot - file), file);
        snprintf(ext, en, "%s", dot);
    }
}

/* the `n`th name for a file rolled at `when`: dir/name-<time>.ext, then dir/name-<time>-n.ext */
static void roll_target(const char *path, double when, int local, int n, char *out, size_t len)
{
    char dir[1024], name[512], ext[64], ts[40];
    roll_split(path, dir, sizeof dir, name, sizeof name, ext, sizeof ext);
    time_t t = (time_t)when;
    int ms = (int)((when - (double)t) * 1000.0);
    if (ms < 0)
        ms = 0;
    if (ms > 999)
        ms = 999;
    struct tm tm;
    if (local)
        localtime_r(&t, &tm);
    else
        gmtime_r(&t, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H-%M-%S", &tm);
    if (n == 0)
        snprintf(out, len, "%s/%s-%s.%03d%s", dir, name, ts, ms, ext);
    else
        snprintf(out, len, "%s/%s-%s.%03d-%d%s", dir, name, ts, ms, n, ext);
}

void log_roll_name(const char *path, double when, int local, char *out, size_t n)
{
    roll_target(path, when, local, 0, out, n);
}

/* Whether `file` (a name in the log's directory) is one of `name`/`ext`'s rolled files, and
 * when it was rolled (UTC seconds). */
static int roll_is_rolled(const char *file, const char *name, const char *ext, int local, double *when)
{
    size_t nl = strlen(name), el = strlen(ext);
    if (strncmp(file, name, nl) != 0 || file[nl] != '-')
        return 0;
    const char *p = file + nl + 1;
    int y, mo, d, h, mi, se, ms, used = 0;
    if (sscanf(p, "%4d-%2d-%2dT%2d-%2d-%2d.%3d%n", &y, &mo, &d, &h, &mi, &se, &ms, &used) != 7 || used != 23)
        return 0;
    p += used;
    if (*p == '-') {   /* a second roll in the same millisecond */
        p++;
        if (*p < '0' || *p > '9')
            return 0;
        while (*p >= '0' && *p <= '9')
            p++;
    }
    if (strncmp(p, ext, el) != 0)
        return 0;
    p += el;
    if (*p && strcmp(p, ".gz") != 0)
        return 0;
    struct tm tm = { 0 };
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = se;
    tm.tm_isdst = -1;
    *when = (double)(local ? mktime(&tm) : timegm(&tm)) + ms / 1000.0;
    return 1;
}

typedef struct {
    char  *rolled;    /* the file just rolled, to compress */
    char  *path;      /* the log's own path, whose rolled files are counted */
    int    keep;
    double keep_for;
    int    gzip;
    int    local;
} roll_job_t;

/* `from` into `from`.gz (written as .gz.tmp, then renamed), and `from` removed; 0 or -1 */
static int roll_gzip(const char *from)
{
#ifdef LIMER_ENCODE
    char tmp[1200], to[1200];
    snprintf(to, sizeof to, "%s.gz", from);
    snprintf(tmp, sizeof tmp, "%s.gz.tmp", from);
    int in = open(from, O_RDONLY | O_CLOEXEC);
    if (in < 0)
        return -1;
    gzFile g = gzopen(tmp, "wb6");
    if (!g) {
        close(in);
        return -1;
    }
    char buf[65536];
    ssize_t k;
    int bad = 0;
    off_t total = 0;
    /* to its end, and again if lines came while it was read (a worker yet to look at the path) */
    for (;;) {
        while ((k = read(in, buf, sizeof buf)) > 0) {
            if (gzwrite(g, buf, (unsigned)k) != (int)k) {
                bad = 1;
                break;
            }
            total += k;
        }
        if (k < 0)
            bad = 1;
        struct stat st;
        if (bad || fstat(in, &st) < 0 || st.st_size <= total)
            break;
    }
    close(in);
    if (gzclose(g) != Z_OK)
        bad = 1;
    if (bad || rename(tmp, to) < 0) {
        unlink(tmp);
        return -1;
    }
    unlink(from);
    return 0;
#else
    (void)from;
    return -1;
#endif
}

typedef struct {
    char  *file;
    double when;
} rolled_t;

static int rolled_newest_first(const void *a, const void *b)
{
    const rolled_t *x = a, *y = b;
    return x->when < y->when ? 1 : x->when > y->when ? -1 : -strcmp(x->file, y->file);
}

/* The log's rolled files past `keep` (newest first) or older than `keep_for`, removed. */
static void roll_cleanup(const char *path, int keep, double keep_for, int local)
{
    char dir[1024], name[512], ext[64];
    roll_split(path, dir, sizeof dir, name, sizeof name, ext, sizeof ext);
    DIR *d = opendir(dir[0] ? dir : "/");
    if (!d)
        return;
    rolled_t *all = NULL;
    size_t n = 0, cap = 0;
    struct dirent *e;
    double now = now_wall();
    while ((e = readdir(d))) {
        double when;
        /* a compression cut off (the worker exited in it) leaves <rolled>.gz.tmp: removed once it
         * is ten minutes old, which no compression still running is */
        size_t len = strlen(e->d_name);
        if (len > 4 && strcmp(e->d_name + len - 4, ".tmp") == 0) {
            char base[512];
            if (len - 4 < sizeof base) {
                memcpy(base, e->d_name, len - 4);
                base[len - 4] = 0;
                struct stat st;
                char full[1700];
                snprintf(full, sizeof full, "%s/%s", dir, e->d_name);
                if (len > 7 && strcmp(base + len - 7, ".gz") == 0 && roll_is_rolled(base, name, ext, local, &when) &&
                    stat(full, &st) == 0 && now - (double)st.st_mtime > 600)
                    (void)unlink(full);
            }
            continue;
        }
        if (!roll_is_rolled(e->d_name, name, ext, local, &when))
            continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            all = xrealloc(all, cap * sizeof *all);
        }
        all[n].file = xstrdup(e->d_name);
        all[n].when = when;
        n++;
    }
    closedir(d);
    if (n)
        qsort(all, n, sizeof *all, rolled_newest_first);
    for (size_t i = 0; i < n; i++) {
        if ((keep > 0 && i >= (size_t)keep) || (keep_for > 0 && now - all[i].when > keep_for)) {
            char full[1700];
            snprintf(full, sizeof full, "%s/%s", dir, all[i].file);
            if (unlink(full) < 0 && errno != ENOENT)
                LOGW("cannot remove the rolled access log %s: %s", full, strerror(errno));
        }
        free(all[i].file);
    }
    free(all);
}

/* The other workers go on adding lines to a file just rolled until they next look at its path,
 * which each does at most once a second, as it writes (log_roll_tick): compressed, and removed,
 * only once nothing has been added for two seconds, a minute at most. Compressed at once, it had
 * taken with it every line they wrote meanwhile (tests/roll_test.py's steady traffic: 4,498 lines
 * for 38,703 requests; 2026-11-09). */
static void roll_wait_still(const char *f)
{
    struct stat a, b;
    if (stat(f, &a) < 0)
        return;
    for (int i = 0; i < 30; i++) {
        struct timespec ts = { 2, 0 };
        while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
            ;
        if (stat(f, &b) < 0 || (b.st_size == a.st_size && b.st_mtime == a.st_mtime))
            return;
        a = b;
    }
}

static void *roll_work(void *arg)
{
    roll_job_t *j = arg;
    if (j->gzip)
        roll_wait_still(j->rolled);
    /* gone meanwhile: removed by another roll's cleanup, as past roll_keep, while this one waited */
    if (j->gzip && roll_gzip(j->rolled) < 0 && errno != ENOENT)
        LOGW("cannot compress the rolled access log %s: %s", j->rolled, strerror(errno));
    roll_cleanup(j->path, j->keep, j->keep_for, j->local);
    free(j->rolled);
    free(j->path);
    free(j);
    return NULL;
}

/* Compressing and removing, on a thread of its own: a large file must not hold up the worker's
 * connections. It takes no signal: those are the worker's own. */
static void roll_start(const char *rolled, const log_roll_t *r)
{
    roll_job_t *j = xcalloc(1, sizeof *j);
    j->rolled = xstrdup(rolled);
    j->path = xstrdup(r->path);
    j->keep = r->keep;
    j->keep_for = r->keep_for;
    j->gzip = r->gzip;
    j->local = r->local;
    sigset_t all, was;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &was);
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    int started = pthread_create(&t, &a, roll_work, j) == 0;
    pthread_attr_destroy(&a);
    pthread_sigmask(SIG_SETMASK, &was, NULL);
    if (!started)
        roll_work(j);
}

/* `r`'s path opened again, at the number *fd has (so nothing else need change), the file it is
 * on noted. */
static void roll_reopen(int *fd, log_roll_t *r)
{
    int nfd = open(r->path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (nfd < 0) {
        LOGW("cannot reopen the access log %s: %s", r->path, strerror(errno));
        return;
    }
    if (*fd > 2 && nfd != *fd) {
        if (dup2(nfd, *fd) < 0) {
            close(nfd);
            return;
        }
        close(nfd);
        (void)fcntl(*fd, F_SETFD, FD_CLOEXEC);   /* dup2 clears it */
    } else if (*fd <= 2) {
        *fd = nfd;
    }
    struct stat st;
    if (fstat(*fd, &st) == 0) {
        r->dev = (uint64_t)st.st_dev;
        r->ino = (uint64_t)st.st_ino;
    }
}

void log_roll_tick(int *fd, log_roll_t *r, double now)
{
    if (!r || *fd <= 2 || now < r->next_check)
        return;
    r->next_check = now + 1.0;
    struct stat fs, ps;
    if (fstat(*fd, &fs) < 0)
        return;
    /* moved away (rolled by another worker, or by logrotate) or removed: follow the path */
    if (stat(r->path, &ps) < 0 || ps.st_ino != fs.st_ino || ps.st_dev != fs.st_dev) {
        roll_reopen(fd, r);
        return;
    }
    if (r->size == 0 || (size_t)fs.st_size < r->size)
        return;
    char lock[1100];
    snprintf(lock, sizeof lock, "%s.lock", r->path);
    int lfd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (lfd < 0)
        return;
    if (flock(lfd, LOCK_EX | LOCK_NB) < 0) {   /* another worker is rolling it */
        close(lfd);
        return;
    }
    /* still this file, still past the size: no other worker rolled it meanwhile */
    if (stat(r->path, &ps) == 0 && ps.st_ino == fs.st_ino && ps.st_dev == fs.st_dev && (size_t)ps.st_size >= r->size) {
        char to[1200];
        double when = now_wall();
        int n = 0;
        do
            roll_target(r->path, when, r->local, n++, to, sizeof to);
        while (access(to, F_OK) == 0 && n < 1000);
        if (rename(r->path, to) == 0) {
            roll_reopen(fd, r);
            LOGI("access log %s rolled to %s", r->path, to);
            roll_start(to, r);
        } else {
            LOGW("cannot roll the access log %s: %s", r->path, strerror(errno));
        }
    } else {
        roll_reopen(fd, r);
    }
    flock(lfd, LOCK_UN);
    close(lfd);
}

