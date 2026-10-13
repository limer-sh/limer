/* auth.c - HTTP basic authentication against bcrypt (or any crypt(3)) hashes */
#include "limer.h"
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Returns 1 when the Authorization header carries valid credentials. */
int auth_verify(const basic_auth_t *a, const char *authorization)
{
    if (!a || !authorization)
        return 0;
    if (strncasecmp(authorization, "Basic", 5) != 0)
        return 0;
    const char *p = authorization + 5;
    while (*p == ' ' || *p == '\t')
        p++;
    unsigned char dec[1024];
    int n = base64_decode(p, strlen(p), dec, sizeof dec - 1);
    if (n <= 0)
        return 0;
    dec[n] = 0;
    if (memchr(dec, 0, (size_t)n))
        return 0;
    char *colon = strchr((char *)dec, ':');
    if (!colon)
        return 0;
    *colon = 0;
    const char *user = (char *)dec;
    const char *pass = colon + 1;
    struct crypt_data cd;
    memset(&cd, 0, sizeof cd);
    int ok = 0;
    /* always run the hash to keep timing independent of user existence */
    const char *hash = a->nusers ? a->users[0].hash : "$2b$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234";
    for (int i = 0; i < a->nusers; i++)
        if (strcmp(a->users[i].name, user) == 0) {
            hash = a->users[i].hash;
            break;
        }
    char *res = crypt_r(pass, hash, &cd);
    if (res && strcmp(res, hash) == 0) {
        for (int i = 0; i < a->nusers; i++)
            if (strcmp(a->users[i].name, user) == 0 && strcmp(a->users[i].hash, hash) == 0)
                ok = 1;
    }
    memset(dec, 0, sizeof dec);
    memset(&cd, 0, sizeof cd);
    return ok;
}
