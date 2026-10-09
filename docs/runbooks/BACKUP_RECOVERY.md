# Backup and recovery

**Last updated:** 2026-07-30 · **Applies to:** OpenWatch v0.8.4 (Eyrie)

This guide covers backup, restore, and disaster recovery for an OpenWatch
deployment. OpenWatch is a single Go binary (`/usr/bin/openwatch`) that serves
the REST API and the embedded React UI over HTTPS on port `8443`, backed by
PostgreSQL and managed by `systemd`. There is no container runtime, no Redis,
and no separate web tier to back up.

For install and first-run setup, see
[Installation](../guides/INSTALLATION.md). This
document assumes the layout that guide produces.

## What you need to back up

Three things must be backed up together, from the same moment, with the
service stopped. A database dump alone is not a complete backup, and neither
is a dump plus the configuration.

| Item | Path | Why it matters | Recoverable without backup? |
|------|------|----------------|-----------------------------|
| PostgreSQL database | external PostgreSQL server | Hosts, scans, transactions, findings, users, roles, encrypted credentials, audit events, job queue, system config | No |
| Remediation rollback store | `/var/lib/openwatch/kensa/` (`remediation.db` plus its `-wal` and `-shm` files) | Kensa's durable capture of each host's pre-change state. A rollback of an executed or staged fix reads it; PostgreSQL holds only the journal of what happened, not the bytes needed to undo it | No: a fix executed before the loss can no longer be rolled back |
| Credential encryption key | `/etc/openwatch/keys/credential.key` | AES-256 key that encrypts SSH credential passwords, private keys and key passphrases, TOTP MFA secrets, notification channel settings and SSO client secrets in the database. The job-queue signing key is derived from it | No |
| JWT signing key | `/etc/openwatch/keys/jwt_private.pem` | Signs access tokens; losing it means clients re-authenticate (sessions and refresh tokens are in the database and survive) | Partially |
| Database secret | `/etc/openwatch/secrets.env` | Holds `OPENWATCH_DATABASE_DSN` | No |
| Configuration | `/etc/openwatch/openwatch.toml` | Server, database, and logging settings | Re-creatable by hand |
| TLS certificate and key | `/etc/openwatch/tls/cert.pem`, `/etc/openwatch/tls/key.pem` | Serves HTTPS on `8443` | Re-issuable from your CA |

> The rollback store is easy to forget because nothing in the UI names it. It
> is set by the service unit (`OPENWATCH_KENSA_STORE_PATH`) and required by the
> packaging contract to be durable, and it only matters on the day you need to
> undo a remediation. Copy it with the service stopped so the WAL is quiescent.

> The `credential.key` is the most important non-database item. SSH credentials,
> MFA secrets, notification channel settings and SSO client secrets in the
> database are encrypted with it. If you restore a database dump but lose
> `credential.key`, those secrets are unrecoverable: you must re-enter every host
> credential, notification channel and SSO client secret, and users must enroll
> MFA again. Jobs queued under the old key also fail. Back up `credential.key` and the
> database together, and store the key with at least the same protection as the
> database.

The default key paths above come from the shipped configuration; confirm yours with
`sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch check-config'`,
which prints the resolved
`jwt_private_key` and `credential_key_file` paths.

### What you do not need to back up

- **Application logs.** Logs go to the `systemd` journal (`journalctl -u
  openwatch`); `/var/log/openwatch` exists but the journal is primary. Back up
  the journal only if your retention policy requires it.
- **The job queue.** Background jobs use a PostgreSQL-native queue
  (`SKIP LOCKED`) inside the same database, so the database dump already covers
  it. There is no separate queue store to back up.
- **Compliance scan content.** Kensa rules are native YAML bundled with the
  install; they are not user data.

## Backup procedure

> **Before you start**
> - **You need:** a reachable PostgreSQL server, `/var/backups/openwatch/` created `root 0700`, and a passphrase for the encrypted state archive kept in your secrets manager.
> - **Run as:** root, with `/etc/openwatch/secrets.env` loaded into the shell (`set -a; . /etc/openwatch/secrets.env; set +a`).
> - **What changes:** nothing on the OpenWatch host; it writes a dump and an encrypted archive under `/var/backups/openwatch/`.
> - **Verify with:** `pg_restore --list` on the dump and a test restore into a scratch database, as in [Verify a backup](#verify-a-backup).
> - **Recover by:** deleting a bad backup file; a backup never alters the running service.

OpenWatch connects to an external PostgreSQL instance. Run `pg_dump` against
that server. The DSN is in `/etc/openwatch/secrets.env` as
`OPENWATCH_DATABASE_DSN`.

The examples below write to `/var/backups/openwatch/`. Nothing creates that
directory for you; the package creates only `/var/lib/openwatch/backups/`,
where the upgrade scriptlet writes its own pre-upgrade dump (see the
[upgrade procedure](UPGRADE_PROCEDURE.md)). Create it once, readable by no
one but root:

```bash
sudo install -d -m 0700 /var/backups/openwatch
```

### Who runs these commands

Run the backup and restore commands as **root**. `/etc/openwatch/secrets.env`
is `root:openwatch 0640` and `/var/backups/openwatch/` is `root 0700`, so an
ordinary administrator account can read neither, and the service user cannot
read the backup directory. Root loads the DSN and connects as the `openwatch`
database role it names. Load the file into the environment once per shell:

```bash
sudo -i
set -a; . /etc/openwatch/secrets.env; set +a   # exports OPENWATCH_DATABASE_DSN
```

Every block below assumes that root shell.

### Database dump

Use a compressed custom-format dump. It restores faster and supports selective
restore.

```bash
pg_dump "$OPENWATCH_DATABASE_DSN" \
    --format=custom \
    --file="/var/backups/openwatch/openwatch_$(date -u +%Y%m%dT%H%M%SZ).dump"
```

The timestamp uses UTC (ISO 8601). For a plain-text dump you can inspect, drop
`--format=custom` and redirect to a `.sql` file.

### Configuration, keys and the rollback store

Back up the keys, secrets and the Kensa rollback store alongside the database
dump, from the same moment. These are secrets: store them encrypted and
restrict access. Stop the service first so the SQLite store is not mid-write.

```bash
systemctl stop openwatch
tar czf - \
    /etc/openwatch/keys/ \
    /etc/openwatch/secrets.env \
    /etc/openwatch/openwatch.toml \
    /etc/openwatch/tls/ \
    /var/lib/openwatch/kensa/ \
  | openssl enc -aes-256-cbc -salt -pbkdf2 \
      -out "/var/backups/openwatch/state_$(date -u +%Y%m%dT%H%M%SZ).tar.gz.enc"
systemctl start openwatch
```

For a consistent set, take the database dump inside the same stop window.

### Verify a backup

A backup you have not verified is not a backup. List the contents of a dump
without restoring it:

```bash
pg_restore --list /var/backups/openwatch/openwatch_<timestamp>.dump >/dev/null \
  && echo "dump readable"
```

For a stronger check, restore into a throwaway database and compare row counts:

```bash
createdb "$RESTORE_DSN_DB"
pg_restore --dbname="$RESTORE_DSN" --no-owner --no-privileges \
    /var/backups/openwatch/openwatch_<timestamp>.dump
psql "$RESTORE_DSN" -c \
    "SELECT 'hosts' AS t, count(*) FROM hosts
     UNION ALL SELECT 'scan_runs', count(*) FROM scan_runs
     UNION ALL SELECT 'users', count(*) FROM users;"
dropdb "$RESTORE_DSN_DB"
```

Scans live in `scan_runs` and `scan_results`; there is no `scans` table. If a
query names a table your schema does not have, the authoritative list is the
set of migrations the binary applied (`openwatch migrate --status`).

### Scheduling

Run the database dump and the state archive on a schedule that meets your
recovery point objective. A `systemd` timer or `cron` entry that calls a
wrapper script covering both, inside one stop window, is sufficient. The
upgrade scriptlet also leaves a pre-upgrade dump in
`/var/lib/openwatch/backups/` on every package upgrade; that is a restore
point for the schema, not a substitute for this schedule. That dump is plain
SQL, not the custom format this guide's `pg_restore` commands read. Restore it
with the steps in the upgrade procedure's
[Full rollback](UPGRADE_PROCEDURE.md#full-rollback-the-schema-advanced). Apply a
retention policy (for example, `find /var/backups/openwatch -name '*.dump'
-mtime +30 -delete`) and copy backups off-host.

## Restore procedure

> **Before you start**
> - **You need:** the database dump and the state archive from the same backup generation, plus its passphrase.
> - **Run as:** root, with `/etc/openwatch/secrets.env` loaded into the shell.
> - **What changes:** the entire database (`--clean --if-exists` replaces current contents), `credential.key`, and the rollback store; the service is stopped for the duration.
> - **Verify with:** `pg_restore` exit 0, then the checks in [Prove the restored service works](#prove-the-restored-service-works): the rule library loaded and one scan completed. Health alone is not proof. Last, a signed-in check that an executed remediation still offers **Roll back**.
> - **Recover by:** restoring the previous generation the same way; take a fresh dump of the current state first if it has any value.

### Restore the database

1. Stop the service so nothing writes while you restore:

   ```bash
   systemctl stop openwatch
   ```

2. Restore into the OpenWatch database. With a custom-format dump, the
   connection goes in `--dbname` and the dump is the only positional
   argument:

   ```bash
   pg_restore --dbname="$OPENWATCH_DATABASE_DSN" \
       --clean --if-exists --no-owner --no-privileges \
       /var/backups/openwatch/openwatch_<timestamp>.dump
   echo "pg_restore exit $?"
   ```

   The exit status must be 0. `--clean --if-exists` drops existing objects
   first, so the restore replaces current contents. If you restore into a
   fresh, empty database instead, omit those flags.

3. Apply any migrations newer than the dump (a no-op when the schema is
   already current; `migrate --status` tells you):

   ```bash
   openwatch migrate --status
   openwatch migrate
   ```

4. Restore the configuration, keys and rollback store (next section), then
   start the service with the checks in
   [Prove the restored service works](#prove-the-restored-service-works).
   Do not start it with a bare `systemctl start` and a health check: health
   reports `healthy` even when the rule library failed to load and every scan
   fails.

### Restore configuration, keys and the rollback store

Restore `credential.key` and the rollback store from the same backup
generation as the database dump. A mismatched key cannot decrypt stored
credentials; a mismatched store describes host states the database does not
know about.

```bash
systemctl stop openwatch
openssl enc -aes-256-cbc -d -pbkdf2 \
    -in /var/backups/openwatch/state_<timestamp>.tar.gz.enc \
  | tar xzf - -C /

chown openwatch:openwatch /etc/openwatch/keys/credential.key
chmod 0600 /etc/openwatch/keys/credential.key
chown -R openwatch:openwatch /var/lib/openwatch/kensa
```

Then start the service with the checks in
[Prove the restored service works](#prove-the-restored-service-works). After
those pass, sign in, open a host that had an executed remediation, and
confirm its **Roll back** control is still offered. That control is what the
rollback store buys you.

### Prove the restored service works

A `200` from `/api/v1/health` does not prove the service works. On a host
where the Kensa rule library fails to load, the service still starts, health
still answers `healthy`, and every scan and remediation fails. The service
logs that only as a warning (CP `bugs/OW-094`). So a restore is done only
when both blocks below finish:

1. The first block restarts the service and proves it loaded its rule
   library. It prints `VERIFIED` only after every check passes.
2. The second block runs one compliance scan end to end. It prints
   `SCANNED` only when the scan completes with no rule errors. On OpenWatch
   0.7.0 through 0.8.1, run the
   [session-based scan check](#run-one-scan-end-to-end-with-a-user-session)
   instead, because those versions cannot start a scan with an API token.

Other runbooks send you here after a restart, because the same blind spot
applies to any restart.

Each block runs in a subshell with `set -euo pipefail`. Any failed check
stops the block, prints the line it stopped on and what was or was not
changed, and prints no success line. A block that stops on a bad input, such
as a missing token file or an unfilled value, has not touched the service.

#### The API tokens

Both blocks call the API with a token passed to `curl` on standard input, so
the token never appears in the process list or the shell history. Neither
block prints it.

| Block | Permission it needs | A built-in role that has it |
|---|---|---|
| Rule library check | `scan:read` | `viewer` |
| Scan check | `host:write` and `scan:read` | `ops_lead`, `security_admin` or `admin` |

The session-based scan check for 0.7.0 through 0.8.1 uses no token. It signs in
as a user, as described in its own section.

The token must be valid in the database the service is running on. After a
restore, that is the **restored** database: the token must have been created
before the backup you restored was taken, and not revoked since. A token
created after that backup does not exist there, and the API answers `401`.
Keep each token in a root-only file, for example:

```bash
( umask 077; printf '%s' 'owk_<the token>' > /root/openwatch-verify.token )
```

Create the tokens while the service is healthy, before you need a restore,
and keep them with the backup plan.

#### How long the checks wait

The rule library check uses the same request timeouts and health wait as the
upgrade runbook's rollback checks. The numbers are stated once, in the upgrade
procedure's
[How long the checks wait](UPGRADE_PROCEDURE.md#how-long-the-checks-wait).
The scan check states its own wait below, because a scan takes minutes.

These bounds apply to the HTTP checks only. `systemctl restart` and
`journalctl` have their own timing, which these numbers do not bound. A
restart that never returns needs `systemctl status openwatch` and the journal,
not a longer wait.

#### Check that the rule library loaded

Fill in the value at the top, then run the block. If a check after the
restart fails, the block stops the service, so nothing runs half-working.

```bash
(
  set -euo pipefail
  TOKEN_FILE='<root-only-file-holding-an-owk-token-valid-in-the-running-database>'
  URL=https://localhost:8443
  STAGE=inputs
  on_stop() {
    echo "VERIFY STOPPED at line $1, stage: $STAGE." >&2
    case "$STAGE" in
      inputs)
        echo "Nothing was changed. The service was not touched." >&2 ;;
      verify)
        echo "The service did not prove it loaded its rule library. It is being stopped." >&2
        systemctl stop openwatch || echo "Could not stop openwatch; stop it yourself." >&2 ;;
    esac
  }
  trap 'on_stop $LINENO' ERR
  case "$TOKEN_FILE" in
    *'<'*) echo "fill in the value at the top first" >&2; false ;;
  esac
  test -r "$TOKEN_FILE"
  TOKEN=$(cat "$TOKEN_FILE")
  [[ "$TOKEN" == owk_* ]]

  STAGE=verify
  SINCE=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl restart openwatch
  READY=no
  DEADLINE=$((SECONDS + 60))
  while [ "$SECONDS" -lt "$DEADLINE" ]; do
    if curl -skf --connect-timeout 3 --max-time 5 -o /dev/null "$URL/api/v1/health"; then READY=yes; break; fi
    sleep 2
  done
  [ "$READY" = yes ]
  LOG=$(journalctl -u openwatch --since "$SINCE" --no-pager -o cat)
  [[ "$LOG" != *"kensa scan wiring unavailable"* ]]
  [[ "$LOG" != *"kensa rule library unavailable"* ]]
  RULES=$(curl -sk --connect-timeout 3 --max-time 5 -o /dev/null -w '%{http_code}' -K - "$URL/api/v1/rules" <<<"header = \"Authorization: Bearer $TOKEN\"")
  [ "$RULES" = 200 ]
  trap - ERR
  echo "VERIFIED: openwatch restarted, answered health, and loaded its rule library"
)
```

If the block stops after the restart, read
`journalctl -u openwatch -n 200 --no-pager`. A `load rule corpus` error names
the rule file that failed. Check that the installed `kensa-rules` package
matches the installed `openwatch` (`rpm -q openwatch kensa-rules` and
`rpm -V kensa-rules`, or `dpkg-query -W openwatch kensa-rules` and
`dpkg --audit`). Fix the cause, then run the block again.

#### Run one scan end to end

Pick a host that was reachable before the restore. Its ID is in the UI's host
page URL, or in `GET /api/v1/hosts`. Fill in the two values at the top. The
block starts one on-demand scan, prints its ID as soon as the server accepts
it, and polls it until it ends.

**You need:** Python 3 with its standard `json` module, run as `python3`. The
block uses it to read the API's JSON answers. It checks for it before it calls
anything, and stops with `python3 with the json module is required` if it is
missing.

This block never stops or restarts the service. A failed scan does not mean
the service should be taken down, and on a small install it may be the only
thing running. The block reports the failure and leaves the service as it is.

Every request carries `--connect-timeout 3 --max-time 5`, as in the rule
library check. The scan check gives up after at most **920 seconds**: 5 for
the request that starts the scan, a 900-second polling deadline, then one
last poll of at most 5 seconds and a 10-second pause. As above, the bound
covers the HTTP requests and the pauses between them.

```bash
(
  set -euo pipefail
  SCAN_TOKEN_FILE='<root-only-file-holding-an-owk-token-with-host-write-and-scan-read>'
  HOST_ID='<id-of-a-host-that-was-reachable-before-the-restore>'
  URL=https://localhost:8443
  STAGE=inputs
  CODE=none
  SCAN_ID=unknown
  OUTCOME=none
  on_stop() {
    echo "SCAN CHECK STOPPED at line $1, stage: $STAGE." >&2
    case "$STAGE" in
      inputs)
        echo "Nothing was changed. No scan was started, and the service was not touched." >&2
        return ;;
      start)
        echo "Verification interrupted: the request that starts the scan got no usable answer (HTTP status: $CODE)." >&2
        echo "Its outcome is unknown. A scan may have started anyway. Before you run this block again," >&2
        echo "check this host's recent scans: GET /api/v1/scans?host_id=$HOST_ID, or the host's page in the UI." >&2 ;;
      poll)
        case "$OUTCOME" in
          failed)
            echo "Scan failed: scan $SCAN_ID ended failed, or completed with rule errors." >&2 ;;
          unfinished)
            echo "Scan did not finish: scan $SCAN_ID was still queued or running when the wait ended." >&2 ;;
          *)
            echo "Verification interrupted: a request about scan $SCAN_ID failed, so its real state is unknown." >&2 ;;
        esac
        echo "Inspect scan $SCAN_ID (GET /api/v1/scans/$SCAN_ID, or the UI) before you start another scan." >&2 ;;
    esac
    echo "The service was left running. Do not call the restore complete." >&2
  }
  trap 'on_stop $LINENO' ERR
  case "$SCAN_TOKEN_FILE $HOST_ID" in
    *'<'*) echo "fill in the two values at the top first" >&2; false ;;
  esac
  [[ "$HOST_ID" =~ ^[0-9a-fA-F-]{36}$ ]]
  python3 -I -S -c 'import json' >/dev/null 2>&1 || { echo "python3 with the json module is required" >&2; false; }
  test -r "$SCAN_TOKEN_FILE"
  TOKEN=$(cat "$SCAN_TOKEN_FILE")
  [[ "$TOKEN" == owk_* ]]
  AUTH="header = \"Authorization: Bearer $TOKEN\""
  KEY=$(cat /proc/sys/kernel/random/uuid)

  STAGE=start
  RESP=$(curl -sk --connect-timeout 3 --max-time 5 -w '\n%{http_code}' -X POST \
      -H "Idempotency-Key: $KEY" -K - "$URL/api/v1/hosts/$HOST_ID/scans" <<<"$AUTH")
  CODE=${RESP##*$'\n'}
  [ "$CODE" = 202 ]
  SCAN_ID=$(python3 -I -S -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])' <<<"${RESP%$'\n'*}")
  [[ "$SCAN_ID" =~ ^[0-9a-fA-F-]{36}$ ]]
  echo "scan started: $SCAN_ID"

  STAGE=poll
  STATE=unknown
  DEADLINE=$((SECONDS + 900))
  while [ "$SECONDS" -lt "$DEADLINE" ]; do
    OUTCOME=interrupted
    BODY=$(curl -skf --connect-timeout 3 --max-time 5 -K - "$URL/api/v1/scans/$SCAN_ID" <<<"$AUTH")
    STATE=$(python3 -I -S -c 'import json,sys; s=json.load(sys.stdin)["scan"]; print(s["status"], s.get("rules_error"))' <<<"$BODY")
    OUTCOME=unfinished
    case "$STATE" in
      completed*|failed*) break ;;
    esac
    sleep 10
  done
  case "$STATE" in
    "completed 0") ;;
    completed*|failed*) OUTCOME=failed; false ;;
    *) OUTCOME=unfinished; false ;;
  esac
  trap - ERR
  echo "SCANNED: scan $SCAN_ID completed with no rule errors"
)
```

A scan that ends `failed`, or completes with rule errors, means the restore is
not done. Read the scan's `failure_reason` in the UI or at
`GET /api/v1/scans/{id}`, and the service journal. When the block stops before
the server accepted the scan, a scan may still have started: look at the host's
recent scans before you start another one.

#### Run one scan end to end with a user session

Use this check instead of the one above when the restored or rolled-back
service runs OpenWatch 0.7.0 through 0.8.1, including the 0.8.0 release
candidates. On those versions, a scan started with an API token answers HTTP
`500`, even though the scan runs (CP `bugs/OW-097`). The token-based check
above therefore always stops at stage `start` on them. The `500` was
reproduced on a running 0.7.1 service. For the other versions the evidence is
source inspection, not a runtime reproduction: the scan handler file is
identical from 0.7.0 through 0.8.1, and it records an API token's own ID as the
scan's requester, a column that accepts only a user. A scan started from a
signed-in user session records the user and starts normally on those
versions, so this check starts its scan that way.

**You need:**

- A user account that holds `host:write` and `scan:read`, such as one with the
  `ops_lead`, `security_admin` or `admin` role. The account must not use MFA:
  the check cannot answer an MFA prompt. It must exist in the database the
  service runs on, which after a restore is the restored database.
- That user's password in a root-only file, for example:

  ```bash
  ( umask 077; cat > /root/openwatch-verify.password )
  ```

  Type the password, press Enter, then Ctrl-D. The check ignores line breaks
  at the end of the file.
- Python 3 with its standard `json` module, run as `python3`, as above.

**How it keeps the password out of sight.** A short Python step reads the
password file and writes the sign-in request to `curl` on standard input. The
password never appears in a command line, the process list, the shell history
or the block's output. The access token the server returns stays in a shell
variable and is passed to `curl` on standard input, as in the token-based
check. The session cookie lives in a private temporary directory that the
check removes when it exits.

**How it signs out, and how it proves it.** The check signs out whenever the
sign-in left a session cookie, whether the scan passed or the check stopped.
From 0.8.0-rc.6 on, sign-out requires the double-submit CSRF token: the
`XSRF-TOKEN` cookie that sign-in set, sent back in the `X-CSRF-Token` header.
Without it, sign-out answers `403` and revokes nothing (CP `bugs/OW-106`). The
check reads that cookie from its own cookie jar and sends it on every
version; earlier versions set the same cookie and ignore the header. The
token goes to `curl` on standard input, like the access token.
That includes a sign-in that set the cookie and then timed out or broke off.
When the sign-in got no answer and left no cookie, the check cannot know
whether the server created a session. It says the outcome is unknown, and you
should check that user's sessions or sign the user out in the UI. It says
there is no session only when the sign-in was refused and set no cookie.
Sign-out answers
`204` even when it revokes nothing, so that answer alone proves nothing. The
check sends the session cookie again after sign-out and expects `401`. Only
both answers together count as proof: `204` from sign-out, then `401` for the
cookie. Any other answer, a timeout, a refused connection or any other request
failure means the sign-out is not proven. A request that gets no answer is
reported as `no answer` and never counts as proof. The check prints
`signed out` when the sign-out is proven. Otherwise it prints
`Sign-out not proven` with both answers, and you must sign that user out of
every session in the UI.

**`SCANNED` means both the scan and the sign-out passed.** When the scan
passes, the check first prints
`scan <id> completed with no rule errors (scan result only)`. That line is the
scan's result, and it stands on its own. The check then signs out. It prints
`SCANNED` and exits `0` only when the sign-out is proven. When the sign-out
is not proven, it prints no `SCANNED`, stops at stage `sign-out`, and exits
`2`: the scan passed, but the check as a whole did not.

**What each stop means.** The check stops with `SCAN CHECK STOPPED` and the
stage. A stop at any stage but `sign-out` exits `1`. A stop at `sign-out`
exits `2`. Every stop after sign-in also reports whether the sign-out was
proven.

| Stage | What it means | What to do |
|---|---|---|
| `inputs` | A value at the top is unfilled, or the password file is unreadable. Nothing was sent. | Fill in the values or fix the file. |
| `login` | The sign-in failed, got no answer, or answered `200` without a usable access token. No scan was started. An account with MFA gets a `200` without an access token. | Read the sign-out outcome below the stop. Check the password file before you try again: a wrong password counts toward the account's lockout. For MFA, use another account. |
| `start` | The request that starts the scan got no usable answer. A scan may have started anyway. | Check the host's recent scans before you run the check again, as the message says. |
| `poll` | The scan failed, finished with rule errors, did not finish in time, or a request about it failed. | Inspect the scan by its ID, as the message says. |
| `sign-out` | The scan passed, and its result line stands. The check's own session could not be proven signed out. Exit `2`. | Sign that user out of every session in the UI. Then the restore is done; there is no need to scan again. |

This check never stops or restarts the service. Every request it makes is
bounded. Signing in, signing out and the cookie check each carry
`--connect-timeout 3 --max-time 10`. The scan requests carry
`--connect-timeout 3 --max-time 5`, as in the check above. The check gives up
after at most **950 seconds**: 10 to sign in, the 920 seconds of the scan wait
above, and 20 to sign out and check the cookie.

Fill in the three values at the top, then run the block as root:

```bash
(
  set -euo pipefail
  USER_NAME='<user-with-host-write-and-scan-read-and-no-mfa>'
  PASSWORD_FILE='<root-only-file-holding-that-users-password>'
  HOST_ID='<id-of-a-host-that-was-reachable-before-the-restore>'
  URL=https://localhost:8443
  STAGE=inputs
  CODE=none
  SIGNIN_CODE=none
  SCAN_ID=unknown
  OUTCOME=none
  SIGN_IN=not-started
  SIGNOUT_DONE=no
  JAR_DIR=$(mktemp -d)
  chmod 700 "$JAR_DIR"
  JAR="$JAR_DIR/cookies"
  # Sign-out answers 204 even when it revokes nothing, so the answer alone is
  # not the proof. Only a 204 from sign-out followed by a 401 for the same
  # session cookie proves it. A request that gets no HTTP answer proves
  # nothing: a curl failure is recorded as "no answer", never as a status.
  # Cleanup follows the cookie jar, not whether sign-in finished: a sign-in
  # can set a session cookie and still time out or break off.
  SIGNOUT=not-needed
  sign_out() {
    [ "$SIGNOUT_DONE" = no ] || return 0
    SIGNOUT_DONE=yes
    [ "$SIGN_IN" != not-started ] || return 0
    SIGNOUT=not-proven
    if ! grep -q 'openwatch_session' "$JAR" 2>/dev/null; then
      if [ "$SIGN_IN" = no-answer ]; then
        echo "Sign-in outcome unknown: the sign-in request got no answer, so a session may exist on the server." >&2
        echo "Check the sessions for $USER_NAME, or sign out of every session for $USER_NAME in the UI." >&2
      elif [ "$SIGNIN_CODE" != 200 ]; then
        SIGNOUT=not-needed
        echo "Sign-in was refused and set no session cookie, so there is no session to sign out." >&2
      else
        echo "Sign-out not proven: sign-in answered 200 but set no session cookie to sign out with." >&2
        echo "Sign out of every session for $USER_NAME in the UI." >&2
      fi
      return 0
    fi
    if [ "$SIGN_IN" = no-answer ] || [ "$SIGNIN_CODE" != 200 ] || [ -z "${ACCESS:-}" ]; then
      echo "Sign-in did not finish normally, but it set a session cookie, so the check signs it out." >&2
    fi
    local out after xsrf
    # From 0.8.0-rc.6 on, sign-out requires the double-submit CSRF token: the
    # XSRF-TOKEN cookie that sign-in set, sent back as X-CSRF-Token. Earlier
    # versions set the same cookie and ignore the header. The token goes to
    # curl on standard input, never onto a command line.
    xsrf=$(awk -F'\t' '$6 == "XSRF-TOKEN" { v = $7 } END { print v }' "$JAR" 2>/dev/null) || xsrf=""
    out=$(curl -sk --connect-timeout 3 --max-time 10 -o /dev/null -w '%{http_code}' \
        -b "$JAR" -K - -X POST "$URL/api/v1/auth/logout" <<<"header = \"X-CSRF-Token: $xsrf\"") || out="no answer"
    after=$(curl -sk --connect-timeout 3 --max-time 10 -o /dev/null -w '%{http_code}' \
        -b "$JAR" "$URL/api/v1/rules") || after="no answer"
    if [ "$out" = 204 ] && [ "$after" = 401 ]; then
      SIGNOUT=proven
      echo "signed out: sign-out answered 204, and the check's session cookie now answers 401" >&2
    else
      echo "Sign-out not proven (sign-out: $out, session cookie afterwards: $after)." >&2
      echo "Sign out of every session for $USER_NAME in the UI." >&2
    fi
  }
  on_stop() {
    echo "SCAN CHECK STOPPED at line $1, stage: $STAGE." >&2
    case "$STAGE" in
      inputs)
        echo "Nothing was changed. No scan was started, and the service was not touched." >&2 ;;
      login)
        if [ "$CODE" = "no answer" ]; then
          echo "Sign-in got no answer: the request failed or timed out. No scan was started." >&2
        elif [ "$CODE" = 200 ]; then
          echo "Sign-in answered 200 without a usable access token. An account with MFA gets this answer." >&2
          echo "No scan was started. If the account uses MFA, use an account without it for this check." >&2
        else
          echo "Sign-in failed (HTTP status: $CODE). No scan was started." >&2
          echo "A wrong password counts toward the account's lockout. Check the file before you try again." >&2
        fi ;;
      start)
        echo "Verification interrupted: the request that starts the scan got no usable answer (HTTP status: $CODE)." >&2
        echo "Its outcome is unknown. A scan may have started anyway. Before you run this block again," >&2
        echo "check this host's recent scans: GET /api/v1/scans?host_id=$HOST_ID, or the host's page in the UI." >&2 ;;
      poll)
        case "$OUTCOME" in
          failed)
            echo "Scan failed: scan $SCAN_ID ended failed, or completed with rule errors." >&2 ;;
          unfinished)
            echo "Scan did not finish: scan $SCAN_ID was still queued or running when the wait ended." >&2 ;;
          *)
            echo "Verification interrupted: a request about scan $SCAN_ID failed, so its real state is unknown." >&2 ;;
        esac
        echo "Inspect scan $SCAN_ID (GET /api/v1/scans/$SCAN_ID, or the UI) before you start another scan." >&2 ;;
    esac
    sign_out
    echo "The service was left running. Do not call the restore complete." >&2
    exit 1
  }
  trap 'on_stop $LINENO' ERR
  trap 'rm -rf "$JAR_DIR"' EXIT
  case "$USER_NAME $PASSWORD_FILE $HOST_ID" in
    *'<'*) echo "fill in the three values at the top first" >&2; false ;;
  esac
  [[ "$HOST_ID" =~ ^[0-9a-fA-F-]{36}$ ]]
  python3 -I -S -c 'import json' >/dev/null 2>&1 || { echo "python3 with the json module is required" >&2; false; }
  test -r "$PASSWORD_FILE"

  # The password goes from the file to curl's standard input, never onto a
  # command line. The access token stays in a shell variable.
  STAGE=login
  SIGN_IN=no-answer
  RESP=$(python3 -I -S -c 'import json,sys; print(json.dumps({"username": sys.argv[1], "password": open(sys.argv[2]).read().rstrip("\n")}))' \
      "$USER_NAME" "$PASSWORD_FILE" |
    curl -sk --connect-timeout 3 --max-time 10 -c "$JAR" -w '\n%{http_code}' \
      -H 'Content-Type: application/json' --data-binary @- "$URL/api/v1/auth/login") || { SIGNIN_CODE="no answer"; CODE=$SIGNIN_CODE; false; }
  SIGN_IN=answered
  SIGNIN_CODE=${RESP##*$'\n'}
  CODE=$SIGNIN_CODE
  [ "$CODE" = 200 ]
  ACCESS=$(python3 -I -S -c 'import json,sys; print(json.load(sys.stdin).get("access_token") or "")' <<<"${RESP%$'\n'*}" 2>/dev/null) || ACCESS=""
  [ -n "$ACCESS" ]
  AUTH="header = \"Authorization: Bearer $ACCESS\""
  KEY=$(cat /proc/sys/kernel/random/uuid)

  STAGE=start
  CODE=none
  RESP=$(curl -sk --connect-timeout 3 --max-time 5 -w '\n%{http_code}' -X POST \
      -H "Idempotency-Key: $KEY" -K - "$URL/api/v1/hosts/$HOST_ID/scans" <<<"$AUTH")
  CODE=${RESP##*$'\n'}
  [ "$CODE" = 202 ]
  SCAN_ID=$(python3 -I -S -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])' <<<"${RESP%$'\n'*}")
  [[ "$SCAN_ID" =~ ^[0-9a-fA-F-]{36}$ ]]
  echo "scan started: $SCAN_ID"

  STAGE=poll
  STATE=unknown
  DEADLINE=$((SECONDS + 900))
  while [ "$SECONDS" -lt "$DEADLINE" ]; do
    OUTCOME=interrupted
    BODY=$(curl -skf --connect-timeout 3 --max-time 5 -K - "$URL/api/v1/scans/$SCAN_ID" <<<"$AUTH")
    STATE=$(python3 -I -S -c 'import json,sys; s=json.load(sys.stdin)["scan"]; print(s["status"], s.get("rules_error"))' <<<"$BODY")
    OUTCOME=unfinished
    case "$STATE" in
      completed*|failed*) break ;;
    esac
    sleep 10
  done
  case "$STATE" in
    "completed 0") ;;
    completed*|failed*) OUTCOME=failed; false ;;
    *) OUTCOME=unfinished; false ;;
  esac
  trap - ERR
  echo "scan $SCAN_ID completed with no rule errors (scan result only)"
  sign_out
  if [ "$SIGNOUT" != proven ]; then
    echo "SCAN CHECK STOPPED, stage: sign-out. The scan passed, but the check's sign-out could not be proven." >&2
    echo "The scan result above stands on its own. The check as a whole did not pass." >&2
    echo "Sign out of every session for $USER_NAME in the UI before you call the restore complete." >&2
    exit 2
  fi
  echo "SCANNED: scan $SCAN_ID completed with no rule errors, and the check's session is signed out"
)
```

When it prints `SCANNED`, the restore is done.

**What was run on a real host.** On 2026-10-02 at 22:57 UTC, the previous
version of this block (sha256
`0fbce1e176b6c0b4c51f3bab3a2f35fc2076768c560b8302b366610446b6e43c`) ran on a
real OpenWatch 0.7.1 host. On a normal sign-in it printed a false line:
`Sign-in did not finish normally, but it set a session cookie, so the check signs it out.`
It judged the sign-in by a status the scan start had already overwritten.
Otherwise it behaved as described: it printed the scan-result line, proved the
sign-out by a `204` and then a `401`, printed `SCANNED`, and exited `0`. Three
earlier versions (sha256 `8aa7ed78…`, `becf17f6…` and `2b41eee3…`) also
printed `SCANNED` on that host the same day. The next version, which keeps the
sign-in's status in its own variable, printed `SCANNED` on 0.7.1 on 2026-10-03
and 2026-10-04.

On 2026-10-05 that version and the block above both ran on a real OpenWatch
0.8.2 host, which enforces sign-out CSRF:

- **That version** sent no CSRF token. Sign-out answered `403`, the session
  cookie still answered `200`, and the check stopped at `sign-out` with exit
  `2` (CP `bugs/OW-106`).
- **The block above** answered `204`, then `401`, printed `SCANNED`, and
  exited `0`.

Its stop paths are tested against a stand-in server, with and without sign-out
CSRF (`TestRunbook_SessionScanBlockBehaves`).

## Disaster recovery (rebuild on a new host)

1. Install the OpenWatch package on the new host (`dnf install` or `apt
   install`) per [Installation](../guides/INSTALLATION.md). This
   creates the `openwatch` user, the binary, `/etc/openwatch/`, and the
   `systemd` unit.
2. Provision PostgreSQL and create the database. The package does not provision
   PostgreSQL.
3. Restore `/etc/openwatch/keys/`, `/etc/openwatch/secrets.env`,
   `/etc/openwatch/openwatch.toml`, `/etc/openwatch/tls/` and
   `/var/lib/openwatch/kensa/` from the encrypted state archive.
4. Restore the database dump into the new PostgreSQL database (see above).
5. Run `openwatch migrate` to apply any pending migrations.
6. Validate config and enable the service at boot:

   ```bash
   sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch check-config'
   sudo systemctl enable openwatch
   ```

7. Start it with the checks in
   [Prove the restored service works](#prove-the-restored-service-works).
   Both blocks must finish before the rebuild is done.

### Recovery objectives

| Scenario | Procedure | Recovery point |
|----------|-----------|----------------|
| Service crash / bad config | Fix config; `openwatch check-config`; then [Prove the restored service works](#prove-the-restored-service-works) | None (no data loss) |
| Database corruption | Restore latest dump; `openwatch migrate` | Last dump |
| Full host loss | Rebuild on new host (above) | Last dump + last key backup |
| Lost `credential.key` | No recovery for stored secrets; re-enter host credentials after restore | Credentials lost |

Measure your actual recovery time against these scenarios; the numbers depend
on database size and your storage.

## Operational runbooks

These cover the common operational alarms for the single binary on `systemd`
with PostgreSQL.

### SERVICE_DOWN: the API is unreachable

```bash
sudo systemctl status openwatch
journalctl -u openwatch -n 100 --no-pager
```

Common causes and checks:

- **Database unreachable.** The log shows `failed to open db pool`. Verify
  `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env` and that PostgreSQL
  is up: `psql "$OPENWATCH_DATABASE_DSN" -c 'SELECT 1;'`.
- **Missing signing or credential key.** The log shows
  `identity.jwt_private_key is empty` or a key-load failure. Confirm the key
  files exist at the paths from `openwatch check-config`.
- **TLS cert or key missing/unreadable.** The log mentions `cert.pem`. Confirm
  `/etc/openwatch/tls/` files exist and the `openwatch` user can read the key.
- **Invalid config.** Run
  `sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch check-config'`;
  it validates and prints the resolved config with secrets redacted.

After fixing the cause, restart the service with the checks in
[Prove the restored service works](#prove-the-restored-service-works). A
`200` from `/api/v1/health` alone does not show that scans work.

### DISK_FULL: a filesystem is out of space

```bash
df -h
journalctl --disk-usage
du -sh /var/lib/openwatch /var/log/openwatch /var/backups/openwatch 2>/dev/null
```

Likely sources and actions:

- **Journal growth.** Vacuum old logs: `sudo journalctl --vacuum-time=7d` (or
  `--vacuum-size=500M`).
- **Old backups.** Prune per your retention policy under
  `/var/backups/openwatch`.
- **Database growth on the PostgreSQL host.** Inspect with
  `psql "$OPENWATCH_DATABASE_DSN" -c "SELECT pg_size_pretty(pg_database_size(current_database()));"`.
  OpenWatch uses a write-on-change transaction model (one row per host×rule plus
  change records), so steady-state growth is bounded; sudden growth usually
  means the audit-event or job-queue tables. Investigate before deleting
  rows. Do not hand-edit OpenWatch tables.

If the service stopped because the disk filled, free space, then restart it
with the checks in
[Prove the restored service works](#prove-the-restored-service-works).

### HIGH_CPU: the host is CPU-saturated

```bash
top -b -n1 | head -20
systemctl status openwatch
journalctl -u openwatch -n 200 --no-pager | grep -iE 'scheduler|worker|scan'
```

- Confirm whether the `openwatch` process or PostgreSQL is the consumer. Scan
  fan-out and the intelligence/discovery schedulers drive most OpenWatch CPU
  use.
- On the PostgreSQL host, look for expensive queries:
  `psql "$OPENWATCH_DATABASE_DSN" -c "SELECT pid, state, query_start, left(query,80) FROM pg_stat_activity WHERE state <> 'idle' ORDER BY query_start;"`.
- The schedulers honor a maintenance switch. To pause intelligence collection
  while you investigate, an admin reads `GET /api/v1/system/intelligence/config`,
  sets `maintenance_global` to `true` inside its `config` object, and `PUT`s
  that whole object back. A body carrying only `maintenance_global` is refused.
  The discovery equivalent is at `/api/v1/system/discovery/config`. The
  startup log notes when either is paused.
- As a last resort, `sudo systemctl restart openwatch` clears any runaway
  in-process loop without losing data (queued jobs resume).

### SECURITY_INCIDENT: suspected compromise

1. **Preserve evidence first.** Capture the journal and audit trail before
   changing anything:

   ```bash
   journalctl -u openwatch --since "-24h" > /var/backups/openwatch/incident_journal.txt
   ```

   OpenWatch writes structured audit events (auth, authz, system lifecycle) to
   the database; export the relevant rows for the incident window before any
   restore.

2. **Contain.** Stop the service to halt active sessions and scans:
   `sudo systemctl stop openwatch`. If only network exposure is the concern,
   firewall port `8443` instead.

3. **Rotate secrets.** If a key may be exposed:
   - Rotate the database password and update
     `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env`.
   - Replace the TLS certificate and key in `/etc/openwatch/tls/`.
   - Rotating the JWT signing key (`/etc/openwatch/keys/jwt_private.pem`)
     invalidates access tokens only. Browser sessions, refresh tokens and API
     tokens are database rows and survive; revoke them separately, as
     [Rotate the JWT signing key](SECRET_ROTATION.md#rotate-the-jwt-signing-key)
     describes.
   - The credential DEK (`/etc/openwatch/keys/credential.key`) cannot be rotated
     by swapping the file alone: every secret listed above is encrypted under it.
     Follow [Rotate the credential DEK](SECRET_ROTATION.md#rotate-the-credential-dek).

4. **Review access.** Audit user accounts and role assignments. Roles and
   permissions are defined in
   [User roles](../guides/USER_ROLES.md).

5. **Recover.** If integrity is in doubt, rebuild on a clean host from a
   known-good backup using the disaster-recovery procedure above, then rotate
   all credentials again.

## Not yet implemented

The following are not part of OpenWatch today. Do not script against them.

- **No built-in backup command.** There is no `openwatch backup` or
  `openwatch restore` subcommand (the full list is in the
  [environment reference](../guides/ENVIRONMENT_REFERENCE.md#cli-subcommands)).
  Use `pg_dump`/`pg_restore` and file copies as shown above.
- **No continuous WAL archiving or point-in-time recovery shipped by
  OpenWatch.** If you need PITR, configure it on your PostgreSQL server
  independently; it is a PostgreSQL feature, not an OpenWatch one.
- **No automated off-site replication.** Copying backups off-host is your
  responsibility.

## Reference

| Item | Value |
|------|-------|
| Binary | `/usr/bin/openwatch` |
| Service unit | `openwatch.service` (`User=openwatch`) |
| Config | `/etc/openwatch/openwatch.toml` |
| DB secret | `/etc/openwatch/secrets.env` (`OPENWATCH_DATABASE_DSN`) |
| Encryption keys | `/etc/openwatch/keys/` (`jwt_private.pem`, `credential.key`) |
| TLS | `/etc/openwatch/tls/{cert,key}.pem` |
| Data / logs | `/var/lib/openwatch`, `/var/log/openwatch` (journal is primary) |
| Health probe | `GET https://<host>:8443/api/v1/health` |
| Migrate | `sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch migrate'` |
| Logs | `journalctl -u openwatch -f` |

See also: [Installation](../guides/INSTALLATION.md),
[User roles](../guides/USER_ROLES.md), and the API contract the binary serves at `/api/v1/openapi.yaml`.
