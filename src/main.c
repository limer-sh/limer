/*
 * main.c - command line interface and process supervision.
 *
 *   limer run [-c Limerfile]      run in the foreground (like `caddy run`)
 *   limer validate [-c Limerfile] check a configuration file
 *   limer reload [-c Limerfile]   ask a running instance to reload
 *   limer stop [-c Limerfile]     ask a running instance to stop
 *   limer version
 */
#include "limer.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *default_config_paths[] = { "Limerfile", "/etc/limer/Limerfile", NULL };

static void usage(FILE *out)
{
    fputs("limer.sh " LIMER_VERSION " - HTTP load balancer with payload-based distribution\n"
          "\n"
          "Usage:\n"
          "  limer run      [-c FILE] [-w N]   Run the load balancer (foreground)\n"
          "  limer validate [-c FILE]          Validate the configuration and exit\n"
          "  limer reload   [-c FILE]          Reload the configuration of a running instance\n"
          "  limer upgrade  [-c FILE]          Replace the running binary with no downtime\n"
          "  limer stop     [-c FILE]          Gracefully stop a running instance\n"
          "  limer version                     Print the version\n"
          "\n"
          "Options:\n"
          "  -c, --config FILE   Configuration file (default: ./Limerfile, /etc/limer/Limerfile)\n"
          "  -w, --workers N     Override the number of worker processes\n"
          "  -p, --pidfile FILE  Override the pidfile\n"
          "  -v, --verbose       Debug logging\n"
          "  -h, --help          This help\n",
          out);
}

static const char *find_config(const char *explicit)
{
    if (explicit)
        return explicit;
    for (int i = 0; default_config_paths[i]; i++)
        if (access(default_config_paths[i], R_OK) == 0)
            return default_config_paths[i];
    return "Limerfile";
}

/* ------------------------------------------------------------------ */
/* pidfile helpers                                                     */
/* ------------------------------------------------------------------ */

static int write_pidfile(const char *path)
{
    if (!path)
        return 0;
    FILE *f = fopen(path, "w");
    if (!f) {
        LOGE("cannot write pidfile %s: %s", path, strerror(errno));
        return -1;
    }
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
    return 0;
}

static pid_t read_pidfile(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    int pid = -1;
    if (fscanf(f, "%d", &pid) != 1)
        pid = -1;
    fclose(f);
    return pid;
}

/* ------------------------------------------------------------------ */
/* master / workers                                                    */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t m_got_hup, m_got_term, m_got_chld, m_got_usr2, m_got_alarm;
static char **g_argv;   /* this process's argv, for re-exec on a graceful upgrade */

static uint64_t sh_load(uint64_t *s, int i)
{
    return s ? __atomic_load_n(&s[i], __ATOMIC_RELAXED) : 0;
}

/* Write `len` bytes (or, with src_path, the contents of that file) to dst
 * through a temporary file renamed into place, so dst is never half-written.
 * Mode and owner follow `like` when it exists. */
static int replace_file(const char *dst, const char *src_path, const char *data, size_t len, mode_t mode, const char *like)
{
    char tmp[1200];
    snprintf(tmp, sizeof tmp, "%s.limer-tmp", dst);
    struct stat st;
    int have_like = like && stat(like, &st) == 0;
    if (have_like)
        mode = st.st_mode & 07777;
    int o = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (o < 0)
        return -1;
    int rc = 0;
    if (src_path) {
        int in = open(src_path, O_RDONLY | O_CLOEXEC);
        if (in < 0) {
            rc = -1;
        } else {
            char buf[65536];
            ssize_t n;
            while ((n = read(in, buf, sizeof buf)) > 0)
                if (write(o, buf, (size_t)n) != n) {
                    rc = -1;
                    break;
                }
            if (n < 0)
                rc = -1;
            close(in);
        }
    } else if (len && write(o, data, len) != (ssize_t)len) {
        rc = -1;
    }
    if (fchmod(o, mode) < 0)
        rc = -1;
    if (have_like)
        (void)!fchown(o, st.st_uid, st.st_gid);
    if (close(o) < 0)
        rc = -1;
    if (rc == 0 && rename(tmp, dst) < 0)
        rc = -1;
    if (rc < 0)
        unlink(tmp);
    return rc;
}

/* Copy the running executable to <dir>/limer.previous so an upgrade can be
 * undone. /proc/self/exe still reads the running image even after the file on
 * disk has been replaced by the new version. */
static int save_running_binary(const char *dir, char *out, size_t outlen)
{
    if (!dir)
        return -1;
    mkdir_p(dir);
    snprintf(out, outlen, "%s/limer.previous", dir);
    return replace_file(out, "/proc/self/exe", NULL, 0, 0755, NULL);
}

/* Keep a rejected file for inspection as <path>.rejected-<timestamp> and put
 * known-good content back at <path>, so a restart of limer or of the machine
 * never picks up what was just rolled back. <path> is replaced atomically. */
static int quarantine(const char *path, const char *good_src, const char *good_text, const char *what)
{
    char stamp[32], rejected[1200];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", &tm);
    snprintf(rejected, sizeof rejected, "%s.rejected-%s", path, stamp);
    if (link(path, rejected) < 0) {
        /* no hard links here: fall back to a copy */
        if (replace_file(rejected, path, NULL, 0, 0644, path) < 0) {
            LOGE("%s: cannot keep a copy of the rejected file as %s: %s", what, rejected, strerror(errno));
            return -1;
        }
    }
    if (replace_file(path, good_src, good_text, good_text ? strlen(good_text) : 0, 0644, path) < 0) {
        LOGE("%s: cannot restore the known-good file at %s: %s", what, path, strerror(errno));
        return -1;
    }
    LOGW("%s: kept the rejected file as %s and restored the known-good one at %s", what, rejected, path);
    return 0;
}

/* Undo a binary upgrade: stop the new workers, and re-exec the saved previous
 * binary in place (same pid), handing it every worker so it can drain them once
 * its own are up. Returns only if the exec failed. */
static void bin_rollback(const char *why, const char *prev_bin, const pid_t *pids, int nworkers,
                         const pid_t *old_pids, int n_old, const sigset_t *unblocked, const sigset_t *block)
{
    LOGW("upgrade rollback: %s; returning to the previous binary", why);
    for (int i = 0; i < nworkers; i++)
        if (pids[i] > 0)
            kill(pids[i], SIGTERM);
    char list[4096];
    size_t off = 0;
    list[0] = 0;
    for (int i = 0; i < n_old && off < sizeof list - 16; i++)
        if (old_pids[i] > 0)
            off += (size_t)snprintf(list + off, sizeof list - off, "%s%d", off ? "," : "", (int)old_pids[i]);
    for (int i = 0; i < nworkers && off < sizeof list - 16; i++)
        if (pids[i] > 0)
            off += (size_t)snprintf(list + off, sizeof list - off, "%s%d", off ? "," : "", (int)pids[i]);
    setenv("LIMER_UPGRADE_WORKERS", list, 1);
    unsetenv("LIMER_PREV_BIN");
    unsetenv("LIMER_BIN_PROBATION");
    /* Put the previous binary back where the new one was installed (keeping the
     * new one as .rejected-<time>), so a restart does not run it again. */
    const char *target = prev_bin;
    char self[1024];
    ssize_t sn = readlink("/proc/self/exe", self, sizeof self - 1);
    if (sn > 0) {
        self[sn] = 0;
        if (!strstr(self, " (deleted)") && strcmp(self, prev_bin) != 0 &&
            quarantine(self, prev_bin, NULL, "upgrade rollback") == 0)
            target = self;
    }
    acme_manager_stop();
    sigprocmask(SIG_SETMASK, unblocked, NULL);
    execv(target, g_argv);
    if (target != prev_bin)
        execv(prev_bin, g_argv);
    sigprocmask(SIG_BLOCK, block, NULL);
    unsetenv("LIMER_UPGRADE_WORKERS");
    LOGE("upgrade rollback: cannot exec %s: %s; staying on the new binary", prev_bin, strerror(errno));
}

static void master_sig(int sig)
{
    switch (sig) {
    case SIGHUP:  m_got_hup = 1;   break;
    case SIGCHLD: m_got_chld = 1;  break;
    case SIGUSR2: m_got_usr2 = 1;  break;
    case SIGALRM: m_got_alarm = 1; break;
    default:      m_got_term = 1;  break;
    }
}

/* Spawn a worker from the master's in-memory (last-known-good) config, inherited
 * across fork. A respawn after a crash therefore never re-reads a config file
 * that may have been edited to something broken in the meantime; the worker
 * still reloads from disk on its own SIGHUP (via cfg->path) when the master,
 * having validated the new config, tells it to. */
static pid_t spawn_worker(config_t *cfg, int id)
{
    pid_t pid = fork();
    if (pid < 0) {
        LOGE("fork: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* worker: reset master signal handlers, run the inherited config */
        signal(SIGHUP, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGUSR2, SIG_DFL);
        signal(SIGALRM, SIG_DFL);
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        int rc = proxy_run(cfg, id);  /* takes ownership of this process's copy */
        _exit(rc);
    }
    return pid;
}

static int run_master(config_t *cfg, const char *cfg_path, const char *pidfile, int nworkers)
{
    pid_t *pids = xcalloc((size_t)nworkers, sizeof(pid_t));
    double *spawned = xcalloc((size_t)nworkers, sizeof(double));
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = master_sig;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* If we are the replacement image of a `limer upgrade`, the previous master
     * left its workers serving and handed us their pids; adopt them so we can
     * drain them once our own workers have bound. */
    pid_t old_pids[256];
    int n_old = 0;
    const char *oldenv = getenv("LIMER_UPGRADE_WORKERS");
    if (oldenv && *oldenv) {
        char tmp[2048];
        snprintf(tmp, sizeof tmp, "%s", oldenv);
        for (char *p = strtok(tmp, ","); p && n_old < 256; p = strtok(NULL, ","))
            old_pids[n_old++] = (pid_t)atoi(p);
    }
    unsetenv("LIMER_UPGRADE_WORKERS");
    int upgrading = n_old > 0;   /* old workers are being retired once the new ones are up */
    int retire_sent = 0;         /* ...and they have already been told to drain */

    /* Response counters shared with the workers (inherited across fork), so the
     * master can judge a reload by the 5xx share that follows it. */
    uint64_t *shared = mmap(NULL, SH_SLOTS * sizeof(uint64_t), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED)
        shared = NULL;
    proxy_set_shared_stats(shared);
    config_t *prev_cfg = NULL;              /* last-known-good config while a reload is on probation */
    int probation = 0;
    double probation_until = 0;
    uint64_t prob_req0 = 0, prob_err0 = 0;  /* counters when the probation began */
    uint64_t prob_oreq0 = 0, prob_oerr0 = 0; /* ...and for the previous config during a canary */
    uint64_t good_req0 = 0, good_err0 = 0;  /* counters when the running config was committed */
    double baseline = 0;                    /* 5xx share of the known-good config */
    rollback_cfg_t rb;
    memset(&rb, 0, sizeof rb);

    /* A binary upgrade made under auto_rollback hands us the saved previous
     * binary: run as a canary next to the old workers until the window passes. */
    int bin_probation = 0;
    int prob_crashes = 0;
    char prev_bin[1024] = "";
    const char *pbin = getenv("LIMER_PREV_BIN");
    const char *pspec = getenv("LIMER_BIN_PROBATION");
    if (upgrading && pbin && *pbin && pspec) {
        double rate = 0.5, win = 15;
        int minr = 20;
        sscanf(pspec, "%lf,%lf,%d", &rate, &win, &minr);
        rb.enabled = 1;
        rb.error_rate = rate;
        rb.window = win;
        rb.min_requests = minr;
        snprintf(prev_bin, sizeof prev_bin, "%s", pbin);
        bin_probation = 1;
    }
    unsetenv("LIMER_PREV_BIN");
    unsetenv("LIMER_BIN_PROBATION");

    if (!upgrading)
        write_pidfile(pidfile);  /* a fresh start owns the pidfile; an upgrade keeps the same pid, so it is still valid */

    LOGI("limer.sh %s master starting %d worker%s%s", LIMER_VERSION, nworkers, nworkers == 1 ? "" : "s",
         bin_probation ? " (upgrade, on probation)" : upgrading ? " (upgrade)" : "");
    for (int i = 0; i < nworkers; i++) {
        pids[i] = spawn_worker(cfg, i);
        spawned[i] = now_mono();
    }
    acme_manager_start(cfg);
    if (upgrading)
        alarm(1);  /* let the new workers bind before draining the old ones */

    int stopping = 0;
    int crashes = 0;
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGHUP);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGCHLD);
    sigaddset(&block, SIGUSR2);
    sigaddset(&block, SIGALRM);
    sigprocmask(SIG_BLOCK, &block, &old);
    for (;;) {
        while (!m_got_hup && !m_got_term && !m_got_chld && !m_got_usr2 && !m_got_alarm)
            sigsuspend(&old);
        if (m_got_term) {
            m_got_term = 0;
            if (!stopping) {
                stopping = 1;
                LOGI("master: stopping workers");
                acme_manager_stop();
                for (int i = 0; i < nworkers; i++)
                    if (pids[i] > 0)
                        kill(pids[i], SIGTERM);
                for (int i = 0; i < n_old; i++)
                    if (old_pids[i] > 0)
                        kill(old_pids[i], SIGTERM);
            }
        }
        if (m_got_hup) {
            m_got_hup = 0;
            if (!stopping && bin_probation) {
                LOGW("reload: ignored while a binary upgrade is on probation; try again in a few seconds");
            } else if (!stopping) {
                char err[512];
                config_lenient_resolve = 1; /* workers keep known addresses for names DNS cannot answer right now */
                config_t *test = config_load(cfg_path, err, sizeof err);
                config_lenient_resolve = 0;
                if (!test) {
                    LOGE("reload: configuration invalid, not reloading workers: %s", err);
                    /* with auto_rollback, also keep the invalid file from being
                     * loaded (or blocking startup) on the next restart */
                    config_t *good = probation ? prev_cfg : cfg;
                    if (good->auto_rollback.enabled && cfg->text)
                        quarantine(cfg_path, NULL, cfg->text, "reload");
                } else {
                    /* The protection in force is the known-good config's, so a new
                     * config cannot switch off its own rollback. */
                    config_t *good = probation ? prev_cfg : cfg;
                    rb = good->auto_rollback.enabled ? good->auto_rollback : test->auto_rollback;
                    int canary = rb.enabled && shared && rb.canary > 0 && rb.canary < 100 ? rb.canary : 0;
                    if (rb.enabled && shared) {
                        if (!probation) {
                            uint64_t r = sh_load(shared, SH_REQ) - good_req0, e = sh_load(shared, SH_ERR) - good_err0;
                            baseline = r ? (double)e / (double)r : 0;
                            __atomic_add_fetch(&shared[SH_CANARY_GEN], 1, __ATOMIC_RELAXED);
                        }
                        /* publish the canary share before the workers reload */
                        __atomic_store_n(&shared[SH_CANARY], (uint64_t)canary, __ATOMIC_RELAXED);
                    }
                    LOGI("master: reloading workers");
                    for (int i = 0; i < nworkers; i++)
                        if (pids[i] > 0)
                            kill(pids[i], SIGHUP);
                    acme_manager_stop();
                    if (rb.enabled && shared) {
                        if (probation)
                            config_unref(cfg);   /* replace the config on probation; prev_cfg stays known-good */
                        else
                            prev_cfg = cfg;      /* hold on to the known-good config */
                        probation = 1;
                        probation_until = now_mono() + rb.window;
                        prob_req0 = sh_load(shared, SH_REQ);
                        prob_err0 = sh_load(shared, SH_ERR);
                        prob_oreq0 = sh_load(shared, SH_OLD_REQ);
                        prob_oerr0 = sh_load(shared, SH_OLD_ERR);
                        alarm(1);
                        if (canary)
                            LOGI("reload: new configuration on probation for %.0fs, taking %d%% of new connections",
                                 rb.window, canary);
                        else
                            LOGI("reload: new configuration on probation for %.0fs", rb.window);
                    } else {
                        config_unref(cfg);
                    }
                    cfg = test;
                    acme_manager_start(cfg);
                }
            }
        }
        if (m_got_usr2) {
            m_got_usr2 = 0;
            if (!stopping && !upgrading) {
                /* Validate the new binary and config in a throwaway child first;
                 * only re-exec in place if it passes, so a broken upgrade leaves
                 * the running server untouched. */
                LOGI("upgrade: validating the new binary");
                pid_t v = fork();
                if (v == 0) {
                    char *va[] = { g_argv[0], (char *)"validate", (char *)"-c", (char *)cfg_path, NULL };
                    execvp(g_argv[0], va);
                    _exit(127);
                }
                int vst = -1;
                if (v > 0)
                    waitpid(v, &vst, 0);
                if (v < 0 || !(WIFEXITED(vst) && WEXITSTATUS(vst) == 0)) {
                    LOGE("upgrade: the new binary or config failed validation; keeping the running server");
                } else {
                    char list[2048];
                    size_t off = 0;
                    list[0] = 0;
                    for (int i = 0; i < nworkers; i++)
                        if (pids[i] > 0)
                            off += (size_t)snprintf(list + off, sizeof list - off, "%s%d", off ? "," : "", (int)pids[i]);
                    setenv("LIMER_UPGRADE_WORKERS", list, 1);
                    /* with auto_rollback, keep a copy of this binary so the new one can be undone */
                    char saved[1024];
                    if (cfg->auto_rollback.enabled) {
                        if (save_running_binary(cfg->storage, saved, sizeof saved) == 0) {
                            char spec[96];
                            snprintf(spec, sizeof spec, "%g,%g,%d", cfg->auto_rollback.error_rate,
                                     cfg->auto_rollback.window, cfg->auto_rollback.min_requests);
                            setenv("LIMER_PREV_BIN", saved, 1);
                            setenv("LIMER_BIN_PROBATION", spec, 1);
                        } else {
                            LOGW("upgrade: cannot save the running binary to %s (%s); the upgrade will not be rolled back automatically",
                                 cfg->storage, strerror(errno));
                        }
                    }
                    acme_manager_stop();  /* the replacement image starts its own certificate manager */
                    LOGI("upgrade: re-executing into the new binary");
                    sigprocmask(SIG_SETMASK, &old, NULL);
                    execvp(g_argv[0], g_argv);
                    /* only reached if exec failed: resume serving unchanged */
                    sigprocmask(SIG_BLOCK, &block, NULL);
                    unsetenv("LIMER_UPGRADE_WORKERS");
                    unsetenv("LIMER_PREV_BIN");
                    unsetenv("LIMER_BIN_PROBATION");
                    acme_manager_start(cfg);
                    LOGE("upgrade: re-exec failed: %s", strerror(errno));
                }
            }
        }
        if (m_got_alarm) {
            m_got_alarm = 0;
            int rearm = 0;
            if (upgrading && !retire_sent && !(bin_probation && probation)) {
                int ready = 1;
                for (int i = 0; i < nworkers; i++)
                    if (pids[i] <= 0)
                        ready = 0;
                if (ready && bin_probation) {
                    /* canary: keep the previous workers serving, judge only the new ones */
                    probation = 1;
                    probation_until = now_mono() + rb.window;
                    prob_req0 = sh_load(shared, 0);
                    prob_err0 = sh_load(shared, 1);
                    baseline = 0;
                    LOGI("upgrade: new binary on probation for %.0fs; the previous workers keep serving alongside it", rb.window);
                    rearm = 1;
                } else if (ready) {
                    LOGI("master: new workers ready, draining the previous ones");
                    for (int i = 0; i < n_old; i++)
                        if (old_pids[i] > 0)
                            kill(old_pids[i], SIGTERM);
                    retire_sent = 1;
                } else {
                    LOGW("master: new workers not up yet, retrying");
                    rearm = 1;
                }
            }
            if (probation && !stopping) {
                uint64_t r = sh_load(shared, 0) - prob_req0, e = sh_load(shared, 1) - prob_err0;
                double share = r ? (double)e / (double)r : 0;
                /* during a canary the yardstick is the previous config over the same window */
                double base = baseline;
                if (!bin_probation && sh_load(shared, SH_CANARY) > 0) {
                    uint64_t orq = sh_load(shared, SH_OLD_REQ) - prob_oreq0, oer = sh_load(shared, SH_OLD_ERR) - prob_oerr0;
                    if (orq >= (uint64_t)rb.min_requests)
                        base = (double)oer / (double)orq;
                }
                if (bin_probation && r >= (uint64_t)rb.min_requests && share >= rb.error_rate) {
                    char why[160];
                    snprintf(why, sizeof why, "%.0f%% of %llu responses from the new binary were 5xx",
                             share * 100, (unsigned long long)r);
                    bin_rollback(why, prev_bin, pids, nworkers, old_pids, n_old, &old, &block);
                    /* exec failed: carry on with the new binary */
                    bin_probation = 0;
                    probation = 0;
                    acme_manager_start(cfg);
                    rearm = 1;
                } else if (bin_probation && now_mono() >= probation_until) {
                    LOGI("upgrade: new binary committed (%.0f%% 5xx over %llu responses); draining the previous workers",
                         share * 100, (unsigned long long)r);
                    for (int i = 0; i < n_old; i++)
                        if (old_pids[i] > 0)
                            kill(old_pids[i], SIGTERM);
                    retire_sent = 1;
                    bin_probation = 0;
                    probation = 0;
                    unlink(prev_bin);
                    good_req0 = sh_load(shared, 0);
                    good_err0 = sh_load(shared, 1);
                } else if (bin_probation) {
                    rearm = 1;
                } else if (r >= (uint64_t)rb.min_requests && share >= rb.error_rate && share > base) {
                    LOGW("auto-rollback: %.0f%% of %llu responses on the new configuration were 5xx (%.0f%% on the previous one); "
                         "reverting to the previous configuration - fix %s and reload",
                         share * 100, (unsigned long long)r, base * 100, cfg_path);
                    __atomic_store_n(&shared[SH_CANARY], 0, __ATOMIC_RELAXED);
                    if (prev_cfg->text)
                        quarantine(cfg_path, NULL, prev_cfg->text, "auto-rollback");
                    config_t *bad = cfg;
                    cfg = prev_cfg;
                    prev_cfg = NULL;
                    probation = 0;
                    /* replace the workers: fresh ones from the known-good config,
                     * the current ones drain once those are up */
                    int alive_old = 0;
                    for (int i = 0; i < n_old; i++)
                        if (old_pids[i] > 0)
                            alive_old = 1;
                    if (!alive_old)
                        n_old = 0;
                    for (int i = 0; i < nworkers; i++)
                        if (pids[i] > 0 && n_old < 256)
                            old_pids[n_old++] = pids[i];
                    for (int i = 0; i < nworkers; i++) {
                        pids[i] = spawn_worker(cfg, i);
                        spawned[i] = now_mono();
                    }
                    upgrading = 1;
                    retire_sent = 0;
                    rearm = 1;
                    acme_manager_stop();
                    acme_manager_start(cfg);
                    config_unref(bad);
                    good_req0 = sh_load(shared, 0);
                    good_err0 = sh_load(shared, 1);
                } else if (now_mono() >= probation_until) {
                    LOGI("reload: new configuration committed (%.0f%% 5xx over %llu responses)",
                         share * 100, (unsigned long long)r);
                    __atomic_store_n(&shared[SH_CANARY], 0, __ATOMIC_RELAXED);  /* workers drop the previous config */
                    config_unref(prev_cfg);
                    prev_cfg = NULL;
                    probation = 0;
                    good_req0 = sh_load(shared, 0);
                    good_err0 = sh_load(shared, 1);
                } else {
                    rearm = 1;
                }
            }
            if (rearm)
                alarm(1);
        }
        if (m_got_chld) {
            m_got_chld = 0;
            int status;
            pid_t p;
            int crash_rollback = 0;
            while ((p = waitpid(-1, &status, WNOHANG)) > 0) {
                /* an adopted old worker finished draining: reap it, never respawn */
                int is_old = 0;
                for (int i = 0; i < n_old; i++)
                    if (old_pids[i] == p) { old_pids[i] = 0; is_old = 1; }
                if (is_old) {
                    int still = 0;
                    for (int i = 0; i < n_old; i++)
                        if (old_pids[i] > 0) still = 1;
                    if (!still && upgrading) {
                        upgrading = 0;
                        retire_sent = 0;
                        LOGI("master: previous workers drained");
                    }
                    continue;
                }
                int is_worker = 0;
                for (int i = 0; i < nworkers; i++)
                    if (pids[i] == p)
                        is_worker = 1;
                if (!is_worker) {
                    LOGW("master: certificate manager exited (%d); it restarts on the next reload", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
                    continue;
                }
                for (int i = 0; i < nworkers; i++) {
                    if (pids[i] != p)
                        continue;
                    pids[i] = 0;
                    if (stopping)
                        break;
                    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                    LOGW("worker %d exited (%s %d), restarting", i,
                         WIFSIGNALED(status) ? "signal" : "status",
                         WIFSIGNALED(status) ? WTERMSIG(status) : code);
                    if (bin_probation && ++prob_crashes >= 2) {
                        crash_rollback = 1;   /* the new binary's workers keep dying: undo the upgrade */
                        break;
                    }
                    if (now_mono() - spawned[i] < 1.0) {
                        if (++crashes > 10) {
                            LOGE("workers are crashing repeatedly, giving up");
                            stopping = 1;
                            for (int k = 0; k < nworkers; k++)
                                if (pids[k] > 0)
                                    kill(pids[k], SIGTERM);
                            for (int k = 0; k < n_old; k++)
                                if (old_pids[k] > 0)
                                    kill(old_pids[k], SIGTERM);
                            break;
                        }
                        sleep(1);
                    } else {
                        crashes = 0;
                    }
                    pids[i] = spawn_worker(cfg, i);
                    spawned[i] = now_mono();
                }
            }
            if (crash_rollback) {
                char why[96];
                snprintf(why, sizeof why, "the new binary's workers crashed %d times", prob_crashes);
                bin_rollback(why, prev_bin, pids, nworkers, old_pids, n_old, &old, &block);
                /* exec failed: carry on with the new binary and refill the worker slots */
                bin_probation = 0;
                probation = 0;
                acme_manager_start(cfg);
                for (int i = 0; i < nworkers; i++)
                    if (pids[i] <= 0) {
                        pids[i] = spawn_worker(cfg, i);
                        spawned[i] = now_mono();
                    }
                alarm(1);
            }
        }
        if (stopping) {
            int alive = 0;
            for (int i = 0; i < nworkers; i++)
                if (pids[i] > 0)
                    alive++;
            for (int i = 0; i < n_old; i++)
                if (old_pids[i] > 0)
                    alive++;
            if (!alive)
                break;
        }
    }
    LOGI("master: all workers stopped");
    config_unref(cfg);
    if (prev_cfg)
        config_unref(prev_cfg);
    if (shared)
        munmap(shared, SH_SLOTS * sizeof(uint64_t));
    free(pids);
    free(spawned);
    if (pidfile && read_pidfile(pidfile) == getpid())
        unlink(pidfile);
    return 0;
}

/* ------------------------------------------------------------------ */
/* commands                                                            */
/* ------------------------------------------------------------------ */

static int cmd_signal(const char *cfg_path, const char *pidfile_override, int sig, const char *verb)
{
    char err[512];
    char *pidfile = pidfile_override ? xstrdup(pidfile_override) : NULL;
    if (!pidfile) {
        config_t *cfg = config_load(cfg_path, err, sizeof err);
        if (!cfg) {
            fprintf(stderr, "limer: %s\n", err);
            return 1;
        }
        pidfile = cfg->pidfile ? xstrdup(cfg->pidfile) : NULL;
        config_unref(cfg);
    }
    if (!pidfile) {
        fprintf(stderr, "limer: no pidfile configured; add `pidfile /path` to the global options or pass --pidfile\n");
        return 1;
    }
    pid_t pid = read_pidfile(pidfile);
    if (pid <= 0) {
        fprintf(stderr, "limer: cannot read pid from %s\n", pidfile);
        free(pidfile);
        return 1;
    }
    if (kill(pid, sig) < 0) {
        fprintf(stderr, "limer: cannot signal pid %d: %s\n", (int)pid, strerror(errno));
        free(pidfile);
        return 1;
    }
    printf("%s requested (pid %d)\n", verb, (int)pid);
    free(pidfile);
    return 0;
}

int main(int argc, char **argv)
{
    g_argv = argv;
    const char *cmd = NULL;
    const char *cfg_opt = NULL;
    const char *pidfile_opt = NULL;
    int workers_opt = -1;
    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-c") == 0 || strcmp(a, "--config") == 0) {
            if (++i >= argc) {
                usage(stderr);
                return 2;
            }
            cfg_opt = argv[i];
        } else if (str_has_prefix(a, "--config=")) {
            cfg_opt = a + 9;
        } else if (strcmp(a, "-w") == 0 || strcmp(a, "--workers") == 0) {
            if (++i >= argc) {
                usage(stderr);
                return 2;
            }
            workers_opt = atoi(argv[i]);
        } else if (strcmp(a, "-p") == 0 || strcmp(a, "--pidfile") == 0) {
            if (++i >= argc) {
                usage(stderr);
                return 2;
            }
            pidfile_opt = argv[i];
        } else if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0 || strcmp(a, "--debug") == 0) {
            verbose = 1;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0 || strcmp(a, "help") == 0) {
            usage(stdout);
            return 0;
        } else if (strcmp(a, "-V") == 0 || strcmp(a, "--version") == 0) {
            cmd = "version";
        } else if (a[0] == '-') {
            fprintf(stderr, "limer: unknown option '%s'\n", a);
            usage(stderr);
            return 2;
        } else if (!cmd) {
            cmd = a;
        } else {
            fprintf(stderr, "limer: unexpected argument '%s'\n", a);
            return 2;
        }
    }
    if (!cmd) {
        usage(stdout);
        return 0;
    }
    if (strcmp(cmd, "version") == 0) {
        const char *features = ""
#ifdef LIMER_TLS
            " tls"
#endif
#ifdef LIMER_H2
            " http/2"
#endif
#ifdef LIMER_H3
            " http/3"
#endif
            ;
        if (*features) {
            /* " tls http/2" -> "(tls, http/2)" */
            char list[64];
            size_t o = 0;
            for (const char *p = features + 1; *p && o < sizeof list - 3; p++) {
                if (*p == ' ') {
                    list[o++] = ',';
                    list[o++] = ' ';
                } else {
                    list[o++] = *p;
                }
            }
            list[o] = 0;
            printf("limer.sh %s (%s)\n", LIMER_VERSION, list);
        } else {
            printf("limer.sh %s\n", LIMER_VERSION);
        }
        return 0;
    }

    const char *cfg_path = find_config(cfg_opt);
    if (strcmp(cmd, "reload") == 0)
        return cmd_signal(cfg_path, pidfile_opt, SIGHUP, "reload");
    if (strcmp(cmd, "upgrade") == 0)
        return cmd_signal(cfg_path, pidfile_opt, SIGUSR2, "upgrade");
    if (strcmp(cmd, "stop") == 0)
        return cmd_signal(cfg_path, pidfile_opt, SIGTERM, "stop");

    char err[512];
    config_t *cfg = config_load(cfg_path, err, sizeof err);
    if (!cfg) {
        fprintf(stderr, "limer: %s: %s\n", cfg_path, err);
        return 1;
    }
    if (strcmp(cmd, "validate") == 0) {
        int nroutes = 0, nups = 0;
        for (int i = 0; i < cfg->nservers; i++)
            for (int r = 0; r < cfg->servers[i]->nroutes; r++) {
                nroutes++;
                if (cfg->servers[i]->routes[r]->pool)
                    nups += cfg->servers[i]->routes[r]->pool->nups;
            }
        printf("%s: valid (%d server block%s, %d route%s, %d upstream%s)\n", cfg_path,
               cfg->nservers, cfg->nservers == 1 ? "" : "s", nroutes, nroutes == 1 ? "" : "s",
               nups, nups == 1 ? "" : "s");
        config_unref(cfg);
        return 0;
    }
    if (strcmp(cmd, "run") != 0) {
        fprintf(stderr, "limer: unknown command '%s'\n", cmd);
        usage(stderr);
        config_unref(cfg);
        return 2;
    }

    if (verbose)
        cfg->log_level = LOG_DEBUG;
    log_level = cfg->log_level;
    if (pidfile_opt) {
        free(cfg->pidfile);
        cfg->pidfile = xstrdup(pidfile_opt);
    }
    int workers = workers_opt > 0 ? workers_opt : cfg->workers;
    if (workers <= 0) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        workers = n > 0 ? (int)n : 1;
    }
    char *pidfile = cfg->pidfile ? xstrdup(cfg->pidfile) : NULL;
    /* Always run under the master supervisor: it owns the pidfile, restarts a
     * crashed worker, and performs no-downtime `limer upgrade`. */
    int rc = run_master(cfg, cfg_path, pidfile, workers); /* takes ownership of cfg */
    free(pidfile);
    return rc;
}
