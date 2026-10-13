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
#include <sys/wait.h>
#include <unistd.h>

static const char *default_config_paths[] = { "Limerfile", "/etc/limer/Limerfile", NULL };

static void usage(FILE *out)
{
    fputs("Limer " LIMER_VERSION " - HTTP load balancer with payload-based distribution\n"
          "\n"
          "Usage:\n"
          "  limer run      [-c FILE] [-w N]   Run the load balancer (foreground)\n"
          "  limer validate [-c FILE]          Validate the configuration and exit\n"
          "  limer reload   [-c FILE]          Reload the configuration of a running instance\n"
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

static volatile sig_atomic_t m_got_hup, m_got_term, m_got_chld;

static void master_sig(int sig)
{
    if (sig == SIGHUP)
        m_got_hup = 1;
    else if (sig == SIGCHLD)
        m_got_chld = 1;
    else
        m_got_term = 1;
}

static pid_t spawn_worker(const char *cfg_path, int id)
{
    pid_t pid = fork();
    if (pid < 0) {
        LOGE("fork: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* worker: reset master signal handlers, load config, run */
        signal(SIGHUP, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        char err[512];
        config_t *cfg = config_load(cfg_path, err, sizeof err);
        if (!cfg) {
            LOGE("worker %d: %s", id, err);
            _exit(2);
        }
        int rc = proxy_run(cfg, id);
        _exit(rc);
    }
    return pid;
}

static int run_master(config_t *cfg, const char *cfg_path, int nworkers)
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
    signal(SIGPIPE, SIG_IGN);

    LOGI("limer %s master starting %d workers", LIMER_VERSION, nworkers);
    for (int i = 0; i < nworkers; i++) {
        pids[i] = spawn_worker(cfg_path, i + 1);
        spawned[i] = now_mono();
    }
    acme_manager_start(cfg);

    int stopping = 0;
    int crashes = 0;
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGHUP);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &old);
    for (;;) {
        while (!m_got_hup && !m_got_term && !m_got_chld)
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
            }
        }
        if (m_got_hup) {
            m_got_hup = 0;
            if (!stopping) {
                char err[512];
                config_t *test = config_load(cfg_path, err, sizeof err);
                if (!test) {
                    LOGE("reload: configuration invalid, not reloading workers: %s", err);
                } else {
                    LOGI("master: reloading workers");
                    for (int i = 0; i < nworkers; i++)
                        if (pids[i] > 0)
                            kill(pids[i], SIGHUP);
                    acme_manager_stop();
                    config_unref(cfg);
                    cfg = test;
                    acme_manager_start(cfg);
                }
            }
        }
        if (m_got_chld) {
            m_got_chld = 0;
            int status;
            pid_t p;
            while ((p = waitpid(-1, &status, WNOHANG)) > 0) {
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
                    LOGW("worker %d exited (%s %d), restarting", i + 1,
                         WIFSIGNALED(status) ? "signal" : "status",
                         WIFSIGNALED(status) ? WTERMSIG(status) : code);
                    if (now_mono() - spawned[i] < 1.0) {
                        if (++crashes > 10) {
                            LOGE("workers are crashing repeatedly, giving up");
                            stopping = 1;
                            for (int k = 0; k < nworkers; k++)
                                if (pids[k] > 0)
                                    kill(pids[k], SIGTERM);
                            break;
                        }
                        sleep(1);
                    } else {
                        crashes = 0;
                    }
                    pids[i] = spawn_worker(cfg_path, i + 1);
                    spawned[i] = now_mono();
                }
            }
        }
        if (stopping) {
            int alive = 0;
            for (int i = 0; i < nworkers; i++)
                if (pids[i] > 0)
                    alive++;
            if (!alive)
                break;
        }
    }
    LOGI("master: all workers stopped");
    config_unref(cfg);
    free(pids);
    free(spawned);
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
#ifdef LIMER_TLS
        printf("limer %s (tls)\n", LIMER_VERSION);
#else
        printf("limer %s\n", LIMER_VERSION);
#endif
        return 0;
    }

    const char *cfg_path = find_config(cfg_opt);
    if (strcmp(cmd, "reload") == 0)
        return cmd_signal(cfg_path, pidfile_opt, SIGHUP, "reload");
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
    if (write_pidfile(pidfile) < 0) {
        config_unref(cfg);
        free(pidfile);
        return 1;
    }
    int rc;
    if (workers == 1) {
        rc = proxy_run(cfg, 0); /* takes ownership of cfg */
    } else {
        rc = run_master(cfg, cfg_path, workers); /* takes ownership of cfg */
    }
    if (pidfile) {
        unlink(pidfile);
        free(pidfile);
    }
    return rc;
}
