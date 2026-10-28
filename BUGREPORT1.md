# Bug report 1: the master hung on the certificate manager (rctuners VPS, 2026-10-28)

Found while adding quillolang.org to the Limerfile on the RC Tuners VPS (104.207.77.212,
`/usr/local/bin/limer`, `limer 0.1.0 (tls)`, installed 2026-10-13 19:00 UTC). The production
traffic moved to Caddy the same day; see "State of the server" at the end.

Five problems. The first was fixed in the source (69a1ebb) but the fix never reached the server;
the fourth and fifth were found while testing the fixes. e80ae13 fixes 2, 3 and 4, the commit
after it fixes 5, both with `tests/reload_test.py` (`make reload`).

| # | Problem | Status |
|---|---|---|
| 1 | A reload restarts the certificate manager, which can't be stopped, and the master hangs on it for good | Fixed in 69a1ebb (2026-10-15), **not deployed** |
| 2 | `limer validate` run as root creates the access log files root-owned, and the next reload is refused | Fixed on `reload-feedback` |
| 3 | `limer reload` / `systemctl reload limer` reports success when the master never acts on it | Fixed on `reload-feedback` |
| 4 | Two reloads close together: the second one's SIGTERM is lost, and the master stalls 5–6 s | Fixed on `reload-feedback` |
| 5 | A reload during a certificate order blocks the master until the order ends (up to 5 s) | Fixed after e80ae13 |

## 1. The master hangs in `acme_manager_stop()`

### What happened

All times UTC, 2026-10-28.

- 09:07: a reload added `quillolang.org` and `www.quillolang.org`. The certificate manager (pid
  12975) began ordering certificates; DNS still pointed at another host, so the orders failed and
  it backed off (60 s, 120 s, 240 s).
- 09:13: a second reload (`systemctl reload limer`). The workers reloaded ("configuration
  reloaded" from both), then the master called `acme_manager_stop()` and never came back.
- 09:15: the manager, still running, obtained both certificates and sent SIGHUP to the master.
  Nothing reloaded: the workers kept serving the temporary self-signed certificate.
- 09:16: another `systemctl reload limer`. Not even "master: reloading workers" was logged.
- 09:18: `systemctl stop limer` (by way of `Conflicts=caddy.service`). The master ignored
  SIGTERM, and systemd killed it at `TimeoutStopSec=20`: "Failed with result 'timeout'".

The workers served traffic throughout. But while the master hung, a worker that died would not
have been restarted, and no reload, upgrade or certificate could take effect.

### What the processes showed (09:16)

```
== 1608 (master)
State:  S (sleeping)
ShdPnd: 0000000000000001      SIGHUP pending
SigBlk: 0000000000014003      HUP, INT, TERM, CHLD blocked (the master's loop mask)
wchan:  do_wait               kernel_wait4 <- __do_sys_wait4
== 12975 (certificate manager, started 09:07, still the same process)
ShdPnd: 0000000000004000      SIGTERM pending, never delivered
SigBlk: 0000000000014003      the same mask, inherited from the master
wchan:  hrtimer_nanosleep     its backoff sleep(1) loop, waiting for manager_stop
```

### Cause

The same one 69a1ebb describes. `acme_manager_start()`, called from the master's loop, forked the
manager with the master's signal mask still blocking SIGTERM, so `manager_sig()` never ran and
`manager_stop` never became 1. `acme_manager_stop()` then waited with a blocking `waitpid(pid,
NULL, 0)`, so the master waited for good.

### Status

Fixed in 69a1ebb, "acme: the certificate manager can always be stopped; upgrades no longer hang":
the child clears its mask (`sigprocmask(SIG_SETMASK, &none, NULL)`) and resets the master's
handlers, and `acme_manager_stop()` waits at most 5 s, then SIGKILLs. `binrollback_test.py` covers
it. The VPS binary is from 2026-10-13, two days older.

**To do:** build `main` for the VPS and install it as `/usr/local/bin/limer` (or with
`limer upgrade`, once the running binary is one that can upgrade without hanging).

Worth adding while there: a regression test that matches this report. Reload, then leave the
manager in its failure backoff (an order that fails, as with DNS pointing elsewhere), then reload
again. The master must log "master: reloading workers" within a few seconds, and the manager's
own SIGHUP after a success must reload the workers.

## 2. `limer validate` as root leaves root-owned log files

### What happened

A new site block had `log { output file /var/log/limer/quillo-website-access.log }`. Running
`limer validate -c /etc/limer/Limerfile.new` as root (to check the change before installing it)
created that file as `root:root 0644`. The service runs as `limer`, so the next reload failed:

```
reload: configuration invalid, not reloading workers: cannot open log file
'/var/log/limer/quillo-website-access.log': Permission denied
```

`chown limer:limer` on the file fixed it.

### Cause

`config_load()` opens each site's log target (`src/config.c:2388`, `s->log_fd =
log_open_target(...)`), and `log_open_target()` (`src/log.c:84`) opens with `O_CREAT`. So
validating a config creates its log files, owned by whoever validated it. The same happens with
`limer reload`, which also calls `config_load()` (in `cmd_signal()`, to find the pidfile) as
whoever runs it, usually root.

### Fix to make

`validate`, and `reload`/`upgrade`/`stop` in `cmd_signal()`, should not create files. Two ways:

- give `config_load()` a "check only" mode in which a missing log file is checked by `access(dir,
  W_OK)` on its directory and an existing one by `access(path, W_OK)`, without opening either; or
- open site log files only in the process that serves (master/workers), never while validating.

Either way, the check should also report the problem the running service will hit: when the file
exists but isn't writable by the configured user, say so ("owned by root; limer runs as limer"),
since a check that passes as root is what hides this one.

## 3. A reload says nothing about whether it happened

`limer reload` sends SIGHUP and prints "reload requested (pid N)"; `systemctl reload limer` (whose
`ExecReload` is `kill -HUP $MAINPID`) prints nothing and exits 0. In this incident a reload was
refused (problem 2) and later ones were never acted on at all (problem 1), and both looked like
successes. The only trace was in the journal.

### Fix to make

Have `limer reload` wait for the outcome and exit non-zero unless it is a success, for example:

- the master bumps a reload generation, with the result (ok, or the error), in shared memory, in
  `<storage>`/`/run/limer`, or on the admin API (`GET /reload` or `GET /status`);
- `limer reload` reads the generation, signals, and waits up to a few seconds for it to move,
  then prints "reloaded" or the error, or "no answer from the master (pid N) in 5 s", exit 1;
- point the unit's `ExecReload=` at `limer reload -c /etc/limer/Limerfile`, so `systemctl reload`
  fails visibly too.

## 4. A reload right after a reload loses the manager's SIGTERM

Found while testing the fixes: three `limer reload`s in a row against a build of `main` (which has
69a1ebb), with the certificate manager failing (CA unreachable):

```
10:05:06.368Z info  [32400] acme: certificate manager started (pid 32412, ...)
10:05:06.369Z info  [32400] master: reloading workers
10:05:12.399Z warn  [32400] acme: certificate manager 32412 did not stop on SIGTERM; killing it
```

The second reload sent SIGTERM 1 ms after the fork, while the child was still closing its
inherited descriptors (the loop runs to 65536). The signal stayed blocked until the child cleared
its mask. It was then delivered to the handler the child had inherited from the master
(`master_sig`), which only sets the master's flag in the child's copy of memory. `manager_main()`
installed `manager_sig` afterwards, but the signal had already been consumed. 69a1ebb's 5 s
SIGKILL fallback kept the master from hanging for good, but it was blocked for 5–6 s each time:
no reloads, no worker supervision, and a slow stop when the stop came right after a fork. The
certificate manager's own SIGHUP after a new certificate can land just like that.

The fix: the child installs the manager's handlers (and clears `manager_stop`) **before** it
clears the mask, so an early SIGTERM reaches `manager_sig`. `tests/reload_test.py` sends four
SIGHUPs 2 ms apart and checks that no manager had to be SIGKILLed. Without the fix it fails in
most runs: it's a race, so not every run.

## What changed on `reload-feedback`

- **2:** `config_check_only` (set by `validate`, and by `reload`, `upgrade` and `stop` when they
  read the Limerfile): `log_check_target()` checks each log file and creates or opens none. An
  existing file must be writable; a missing one needs a writable directory. As root, a
  root-owned file in a directory of another user's is refused, naming that user, which is the
  incident's state. When the server itself can't open a log file, the error now names the
  file's (or directory's) owner and the user limer runs as.
- **3:** the master writes each SIGHUP's outcome to `<pidfile>.reload` (`<pid> <started> ok|error
  <detail>`, replaced atomically). `started` is CLOCK_MONOTONIC when it began handling the
  signal, so `limer reload` takes only an answer that began after its own signal. It waits up
  to 10 s and exits 0 (workers reloading), 1 with the reason (refused config, ignored while an
  upgrade is on probation, stopping), or 1 when nothing answers.
- **4:** `acme_manager_start()` installs the manager's handlers before clearing the mask.

Still not covered: a worker that fails its own reload (for example, a new listener that can't
bind) logs it, but the master's answer has already said "workers reloading".

Tests: `make reload` (15 checks) passes on macOS, on Ubuntu 24.04 as root and as an ordinary user,
and on the VPS. Also passing: unit, integration (99), features (244), security (101), rollback,
binrollback, admin, status, drain, discover, broadcast.

## In production (2026-10-28, 10:20–10:25 UTC)

Built on the VPS from `reload-feedback`, installed as `/usr/local/bin/limer` (the old binary is
`/usr/local/bin/limer.20261013`), and swapped in for Caddy (~1.8 s with nothing listening). A
temporary site, `limer-probe.quillolang.org` (no DNS record, so its orders fail on NXDOMAIN), with
a root-owned access log, replayed the incident:

| Step | Result |
|---|---|
| `limer validate` as root, root-owned log in `/var/log/limer` | Refused: "belongs to root, but /var/log/limer belongs to limer ... (chown limer '...')", exit 1 |
| `systemctl reload limer` | "Job for limer.service failed", exit 1; the unit stayed active/running |
| `limer reload -p` (the master decides) | "reload failed: configuration invalid ... Permission denied (it belongs to root, and limer runs as limer)", exit 1 |
| Owner fixed, reload adding the site (as at 09:07) | Answered in 0.11 s; the order failed on NXDOMAIN and backed off |
| Two reloads during the backoff (as at 09:13) | Answered in 0.07 s each |
| Four raw SIGHUPs 2 ms apart, then a reload | Answered (after 4.2 s: see problem 5); 5 manager starts, none needed SIGKILL |
| `limer upgrade` to the build with the `errno` fix | Same master pid, new workers ready in 1 ms, old ones drained |
| `systemctl restart limer` | Master stopped at once; 10.3 s in all, the Limerfile's `grace 10s` for long-lived streams; no timeout, no SIGKILL |

The production test also caught one bug in the new code, now fixed: `log_check_target()` printed
"Success" for a log file it couldn't write, because `getpwuid()` (in an argument of the same
`snprintf`) reset `errno` before `strerror(errno)` was evaluated.

## 5. The master waits for a manager that is in the middle of an order

Seen in production: a reload reached the master while the certificate manager was in the middle
of an ACME order. The manager checks `manager_stop` only between steps, so it finished the order
(4 s) before exiting, and `acme_manager_stop()` blocked the master that long. The 5 s cap from
69a1ebb bounds it, but for those seconds the master doesn't reload or supervise workers.

Shortening the wait by SIGKILLing sooner isn't safe as the code stands: the order's result is
written as `key.pem`, then `cert.pem` (each atomically, but not as a pair), so a kill between the
two leaves a new key beside the old certificate. (The current 5 s SIGKILL has the same small
window.) The fix (the commit after e80ae13):

- `acme_manager_stop()`, used by reloads, sends SIGTERM and returns. The master reaps the old
  manager on SIGCHLD; `acme_manager_reaped()` tells it the exit was asked for, so it isn't
  reported as a crash (and a manager that exits on its own is forgotten, so its pid is never
  signalled again). Stopping, and an upgrade's re-exec, use `acme_manager_stop_wait()`: every
  manager, 5 s at most, then SIGKILL, as before.
- Every manager holds `flock(<storage>/acme/lock)` while it works, so a new one waits for the
  old one to exit ("waiting for the previous certificate manager to finish"), and only one ever
  orders or writes certificates. The kernel releases the lock even on SIGKILL.
- `https_call()` returns at once when `manager_stop` is set, so an order in progress ends at its
  next request ("order for X left unfinished: the certificate manager is stopping") instead of
  running to the end; the connect and response errors such a stop causes are no longer logged.
  A certificate obtained just before the stop still sends the master its SIGHUP.
- The key and certificate are written to `.tmp` files in full, then renamed one right after
  the other, so a kill can no longer land between writing them. A key that doesn't match its
  certificate (`X509_check_private_key`) makes the renewal check treat the certificate as
  missing, so a new one is ordered at once instead of at renewal time.

Tests: `reload_test.py` stops the newest manager with SIGSTOP (busy, as in an order), then a
reload must be answered at once (it took 6.0 s before the fix), the next manager must wait for
the lock, and the stopped one, continued, must exit on its pending SIGTERM and be reaped without
a warning. A planted key that isn't its certificate's must be ordered again. Against Pebble
(Docker, Ubuntu 24.04), a reload during a real order: the master started the next manager in
the same millisecond, the old one left its order, the new one got the certificate 5.6 s later,
and both stored pairs matched.

Still open, and small: `limer reload` loads every certificate (logging each) just to find the
pidfile.

## Smaller things noticed

- A failed ACME order is retried after 60 s, 120 s, 240 s, … while Let's Encrypt allows 5 failed
  validations per hostname per hour. With DNS pointing elsewhere, the first hour spends six. A
  check before ordering (does the name resolve to one of this host's addresses?) could wait
  without spending any; it would need to allow for a proxy or NAT in front.
- After a certificate is obtained, the workers pick it up only through the master's reload. With
  the master hung, the manager's SIGHUP was lost, and it never tried again. Logging "certificate
  stored; reload pending" until a reload happens would have shown it at once.

## The same sequence on Caddy

Replayed on 2026-10-28 against `caddy:2.6.2` (the VPS's version) in Docker, with Pebble as the
CA and pebble-challtestsrv as the DNS server, so a name could point elsewhere and then at Caddy.
Caddy ran as uid 1000; "as root" means `docker exec -u 0`.

| Limer problem | Caddy 2.6.2, same steps |
|---|---|
| 1. Master hangs after a reload during the ACME backoff | No hang. With an ACME account already stored (as on the VPS): add the site by reload while its DNS points elsewhere (orders fail, retry scheduled), reload again during the backoff (both returned in ~0.1 s, exit 0), then move DNS. The certificate came 6 s later **with no reload** and was served at once. `stop` took 0.15 s. |
| 2. `validate` as root leaves root-owned log files | `caddy validate` as root creates no log files: file writers open on the first write. When the log file already exists root-owned, the reload still succeeds and the site serves; on the first write Caddy moves the unwritable file aside (`<name>-<timestamp>.log`) and starts a new one it owns, logging one `write error: chown ...: operation not permitted` line. |
| 3. Reload reports success whatever happens | `caddy reload` posts the config to the admin API and waits: an invalid config prints the error and exits 1, and the running config stays. |

Caddy has a problem of its own in the same area, which the VPS doesn't hit. With **no ACME
account stored yet** and two names, the first orders run at once and register two accounts
(Pebble: "There are now 2 accounts in memory"); only one key is kept. Without a reload Caddy
recovers. A reload during the backoff, though, left every later order failing with `JWS
verification error: go-jose/go-jose: error in cryptographic primitive`, with no certificate for
the 5 minutes watched. The VPS's Caddy already has its account, so this only matters on a fresh
install.

Ignore one artifact if this is rerun: current Pebble sends `Retry-After` as an HTTP date, which
Caddy 2.6.2 rejects ("response had invalid Retry-After header"), so some finalizations fail and
retry. Let's Encrypt's own servers didn't trigger it: the VPS got real certificates in 3 s.

What this suggests for Limer's fixes: open log files lazily or only check them while validating
(problem 2), and make `limer reload` wait for the result and fail loudly, as `caddy reload` does
(problem 3).

## State of the server

- 2026-10-28 10:20 UTC: **back on Limer**, the `reload-feedback` build (source in
  `/usr/local/src/limer-reload-feedback`), with `ExecReload=/usr/local/bin/limer reload -c
  /etc/limer/Limerfile` in the unit (the previous unit is `limer.service.bak-20261028`). Caddy is
  disabled, with its config intact in `/etc/caddy/sites/` (`quillo.caddy` included), as a fallback:
  `systemctl disable limer && systemctl enable --now caddy`.

Earlier the same day:

- 2026-10-28 09:18 UTC: production moved to Caddy (`systemctl disable limer`, `systemctl enable
  --now caddy`). Caddy serves rctuners.com, www, chat, qa and quillolang.org (+ www) from
  `/etc/caddy/sites/*.caddy`; `quillo.caddy` was added for quillolang.org.
- `/etc/limer/Limerfile` keeps every site, quillolang.org included; the version before
  quillolang.org was added is `/etc/limer/Limerfile.bak-20261028-090534`. Certificates for all
  six names are in `/var/lib/limer/certs/`.
- Going back to Limer once the fixed binary is installed: `limer validate` as the `limer` user
  (`runuser -u limer -- limer validate -c /etc/limer/Limerfile`), then `systemctl disable caddy &&
  systemctl enable --now limer` (`Conflicts=` stops Caddy).
