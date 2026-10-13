/* log.c - leveled logging to stderr and access logging to stdout */
#include "limer.h"
#include <stdlib.h>
#include <string.h>
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
