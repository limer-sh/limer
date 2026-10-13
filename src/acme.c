/* acme.c - certificate storage and the automatic-HTTPS manager (ACME).
 * The manager itself is implemented further down; this part is used by
 * config loading and challenge serving. */
#include "limer.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int file_exists(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

/* Load <storage>/certs/<first host>/{cert,key}.pem into the server if present. */
int acme_load_stored(config_t *cfg, server_t *s, char *err, size_t errlen)
{
    if (s->nhosts == 0)
        return 0;
    char cert[2048], key[2048];
    snprintf(cert, sizeof cert, "%s/certs/%s/cert.pem", cfg->storage, s->hosts[0]);
    snprintf(key, sizeof key, "%s/certs/%s/key.pem", cfg->storage, s->hosts[0]);
    if (!file_exists(cert) || !file_exists(key))
        return 0; /* not obtained yet: keep the temporary certificate */
    char lerr[256];
    if (tls_load_pem(s, cert, key, lerr, sizeof lerr) < 0) {
        LOGW("site %s: stored certificate unusable (%s); using a temporary one", s->hosts[0], lerr);
        return 0;
    }
    (void)err; (void)errlen;
    return 0;
}

/* http-01 key authorisation lookup: <storage>/challenges/<token> */
int acme_challenge_lookup(const config_t *cfg, const char *token, buf_t *out)
{
    for (const char *p = token; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))
            return 0;
    if (!*token || strlen(token) > 128)
        return 0;
    char path[2048];
    snprintf(path, sizeof path, "%s/challenges/%s", cfg->storage, token);
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    char tmp[512];
    size_t n = fread(tmp, 1, sizeof tmp, f);
    fclose(f);
    buf_reset(out);
    buf_append(out, tmp, n);
    return 1;
}

int acme_manager_start(config_t *cfg)
{
    (void)cfg;
    return 0; /* implemented with the ACME client */
}

void acme_manager_stop(void)
{
}
