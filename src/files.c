/* files.c - helpers for the static file server: MIME types, HTTP dates,
 * directory listings and path resolution. */
#include "limer.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

const char *mime_type_for(const char *path)
{
    static const struct { const char *ext; const char *type; } tbl[] = {
        { "html", "text/html; charset=utf-8" }, { "htm", "text/html; charset=utf-8" },
        { "css", "text/css; charset=utf-8" }, { "js", "text/javascript; charset=utf-8" },
        { "mjs", "text/javascript; charset=utf-8" }, { "json", "application/json" },
        { "map", "application/json" }, { "txt", "text/plain; charset=utf-8" },
        { "md", "text/markdown; charset=utf-8" }, { "xml", "application/xml" },
        { "svg", "image/svg+xml" }, { "png", "image/png" }, { "jpg", "image/jpeg" },
        { "jpeg", "image/jpeg" }, { "gif", "image/gif" }, { "webp", "image/webp" },
        { "avif", "image/avif" }, { "ico", "image/x-icon" }, { "bmp", "image/bmp" },
        { "pdf", "application/pdf" }, { "zip", "application/zip" }, { "gz", "application/gzip" },
        { "tar", "application/x-tar" }, { "wasm", "application/wasm" },
        { "woff", "font/woff" }, { "woff2", "font/woff2" }, { "ttf", "font/ttf" }, { "otf", "font/otf" },
        { "mp4", "video/mp4" }, { "webm", "video/webm" }, { "mp3", "audio/mpeg" }, { "ogg", "audio/ogg" },
        { "wav", "audio/wav" }, { "csv", "text/csv; charset=utf-8" }, { "rss", "application/rss+xml" },
        { "atom", "application/atom+xml" }, { "webmanifest", "application/manifest+json" },
        { "yaml", "text/yaml; charset=utf-8" }, { "yml", "text/yaml; charset=utf-8" },
        { "sh", "text/x-shellscript; charset=utf-8" }, { "c", "text/x-c; charset=utf-8" },
        { "h", "text/x-c; charset=utf-8" }, { "py", "text/x-python; charset=utf-8" },
        { NULL, NULL }
    };
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');
    if (!dot || (slash && dot < slash) || !dot[1])
        return "application/octet-stream";
    for (int i = 0; tbl[i].ext; i++)
        if (strcasecmp(dot + 1, tbl[i].ext) == 0)
            return tbl[i].type;
    return "application/octet-stream";
}

void http_date(time_t t, char *out, size_t n)
{
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, n, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

time_t http_date_parse(const char *s)
{
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    const char *fmts[] = { "%a, %d %b %Y %H:%M:%S GMT", "%A, %d-%b-%y %H:%M:%S GMT", "%a %b %d %H:%M:%S %Y", NULL };
    for (int i = 0; fmts[i]; i++) {
        memset(&tm, 0, sizeof tm);
        const char *end = strptime(s, fmts[i], &tm);
        if (end && (*end == 0 || *end == ';'))
            return timegm(&tm);
    }
    return (time_t)-1;
}

static void html_escape(buf_t *b, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '<': buf_puts(b, "&lt;"); break;
        case '>': buf_puts(b, "&gt;"); break;
        case '&': buf_puts(b, "&amp;"); break;
        case '"': buf_puts(b, "&quot;"); break;
        default: buf_append(b, s, 1);
        }
    }
}

static void url_escape(buf_t *b, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (isalnum(c) || strchr("-._~/", c))
            buf_append(b, s, 1);
        else
            buf_printf(b, "%%%02X", c);
    }
}

static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Render an HTML directory listing. urlpath is the request path (ends with '/'). */
int files_listing(const char *dir, const char *urlpath, int hide_dotfiles, buf_t *out)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    char **names = NULL;
    int n = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (hide_dotfiles && de->d_name[0] == '.')
            continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 64;
            names = xrealloc(names, sizeof(char *) * (size_t)cap);
        }
        names[n++] = xstrdup(de->d_name);
    }
    closedir(d);
    qsort(names, (size_t)n, sizeof(char *), cmp_names);
    buf_puts(out, "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>Index of ");
    html_escape(out, urlpath);
    buf_puts(out, "</title><style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}"
                  "td,th{text-align:left;padding:.2em 1em .2em 0}a{text-decoration:none}</style></head><body><h1>Index of ");
    html_escape(out, urlpath);
    buf_puts(out, "</h1><table><tr><th>Name</th><th>Size</th><th>Modified</th></tr>\n");
    if (strcmp(urlpath, "/") != 0)
        buf_puts(out, "<tr><td><a href=\"../\">../</a></td><td></td><td></td></tr>\n");
    for (int i = 0; i < n; i++) {
        char full[4096];
        snprintf(full, sizeof full, "%s/%s", dir, names[i]);
        struct stat st;
        int is_dir = stat(full, &st) == 0 && S_ISDIR(st.st_mode);
        buf_puts(out, "<tr><td><a href=\"");
        url_escape(out, names[i]);
        if (is_dir)
            buf_puts(out, "/");
        buf_puts(out, "\">");
        html_escape(out, names[i]);
        if (is_dir)
            buf_puts(out, "/");
        buf_puts(out, "</a></td><td>");
        if (!is_dir)
            buf_printf(out, "%lld", (long long)st.st_size);
        buf_puts(out, "</td><td>");
        char date[64];
        http_date(st.st_mtime, date, sizeof date);
        buf_puts(out, date);
        buf_puts(out, "</td></tr>\n");
        free(names[i]);
    }
    free(names);
    buf_puts(out, "</table></body></html>\n");
    return 0;
}

/* Does any path segment start with a dot? */
int path_has_dotfile(const char *clean)
{
    for (const char *p = clean; *p; p++)
        if (*p == '/' && p[1] == '.')
            return 1;
    return 0;
}
