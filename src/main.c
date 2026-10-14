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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
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
    uint64_t *shared = mmap(NULL, 2 * sizeof(uint64_t), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED)
        shared = NULL;
    proxy_set_shared_stats(shared);
    config_t *prev_cfg = NULL;              /* last-known-good config while a reload is on probation */
    int probation = 0;
    double probation_until = 0;
    uint64_t prob_req0 = 0, prob_err0 = 0;  /* counters when the probation began */
    uint64_t good_req0 = 0, good_err0 = 0;  /* counters when the running config was committed */
    double baseline = 0;                    /* 5xx share of the known-good config */
    rollback_cfg_t rb;
    memset(&rb, 0, sizeof rb);

    if (!upgrading)
        write_pidfile(pidfile);  /* a fresh start owns the pidfile; an upgrade keeps the same pid, so it is still valid */

    LOGI("limer.sh %s master starting %d worker%s%s", LIMER_VERSION, nworkers,
         nworkers == 1 ? "" : "s", upgrading ? " (upgrade)" : "");
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
            if (!stopping) {
                char err[512];
                config_lenient_resolve = 1; /* workers keep known addresses for names DNS cannot answer right now */
                config_t *test = config_load(cfg_path, err, sizeof err);
                config_lenient_resolve = 0;
                if (!test) {
                    LOGE("reload: configuration invalid, not reloading workers: %s", err);
                } else {
                    LOGI("master: reloading workers");
                    for (int i = 0; i < nworkers; i++)
                        if (pids[i] > 0)
                            kill(pids[i], SIGHUP);
                    acme_manager_stop();
                    /* The protection in force is the known-good config's, so a new
                     * config cannot switch off its own rollback. */
                    config_t *good = probation ? prev_cfg : cfg;
                    rb = good->auto_rollback.enabled ? good->auto_rollback : test->auto_rollback;
                    if (rb.enabled && shared) {
                        if (probation) {
                            config_unref(cfg);   /* replace the config on probation; prev_cfg stays known-good */
                        } else {
                            prev_cfg = cfg;      /* hold on to the known-good config */
                            uint64_t r = sh_load(shared, 0) - good_req0, e = sh_load(shared, 1) - good_err0;
                            baseline = r ? (double)e / (double)r : 0;
                        }
                        probation = 1;
                        probation_until = now_mono() + rb.window;
                        prob_req0 = sh_load(shared, 0);
                        prob_err0 = sh_load(shared, 1);
                        alarm(1);
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
                    acme_manager_stop();  /* the replacement image starts its own certificate manager */
                    LOGI("upgrade: re-executing into the new binary");
                    sigprocmask(SIG_SETMASK, &old, NULL);
                    execvp(g_argv[0], g_argv);
                    /* only reached if exec failed: resume serving unchanged */
                    sigprocmask(SIG_BLOCK, &block, NULL);
                    unsetenv("LIMER_UPGRADE_WORKERS");
                    acme_manager_start(cfg);
                    LOGE("upgrade: re-exec failed: %s", strerror(errno));
                }
            }
        }
        if (m_got_alarm) {
            m_got_alarm = 0;
            int rearm = 0;
            if (upgrading && !retire_sent) {
                int ready = 1;
                for (int i = 0; i < nworkers; i++)
                    if (pids[i] <= 0)
                        ready = 0;
                if (ready) {
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
                if (r >= (uint64_t)rb.min_requests && share >= rb.error_rate && share > baseline) {
                    LOGW("auto-rollback: %.0f%% of %llu responses were 5xx after the reload (%.0f%% before); "
                         "reverting to the previous configuration - fix %s and reload",
                         share * 100, (unsigned long long)r, baseline * 100, cfg_path);
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
        munmap(shared, 2 * sizeof(uint64_t));
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
#if defined(LIMER_TLS) && defined(LIMER_H2)
        printf("limer.sh %s (tls, http/2)\n", LIMER_VERSION);
#elif defined(LIMER_TLS)
        printf("limer.sh %s (tls)\n", LIMER_VERSION);
#else
        printf("limer.sh %s\n", LIMER_VERSION);
#endif
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
