# OpenWatch install guide (native packages)

This guide takes an administrator from a fresh Linux host to a running,
logged-in OpenWatch: install the package, point it at PostgreSQL, create the
first admin user, start the service, and sign in to the web UI.

## What you get

Installing the package gives you a single `systemd`-managed service that serves
both the REST API and the web UI over HTTPS on port 8443. One binary contains
everything — the API, the embedded React UI, and the Kensa compliance engine; no
separate web tier, no container runtime, no external cache.

After the steps below you have:

- The OpenWatch UI and API at `https://<host>:8443/`, behind session login.
- An `admin` account you create during install.
- A PostgreSQL database holding hosts, scans, transactions, and audit events.
- Kensa ready to run SSH-based compliance checks against the hosts you add.

---

## At a glance

| Step | What | Command |
|------|------|---------|
| 1 | Install PostgreSQL | `dnf install postgresql-server` / `apt install postgresql` |
| 2 | Provision the database | `createdb` + role (see below) |
| 3 | Install the packages | `dnf install ./openwatch-*.rpm ./kensa-rules-*.rpm` / `apt install ./openwatch_*.deb ./kensa-rules_*.deb` |
| 4 | Configure the database secret | edit `/etc/openwatch/secrets.env` |
| 5 | Run migrations | `openwatch migrate` |
| 6 | Create the first admin | `openwatch create-admin --username admin --email …` |
| 7 | Start the service | `systemctl enable --now openwatch` |
| 8 | Sign in | open `https://<host>:8443/` |

On a host that already runs PostgreSQL, this takes about five minutes.

---

## Requirements

- **OS:**
  - RPM: CentOS Stream 9, RHEL 9, Rocky Linux 9, AlmaLinux 9, Oracle Linux 9
  - DEB: Ubuntu 24.04 LTS, Debian 12 (or a compatible `systemd` derivative)
- **Architecture:** `x86_64`/`amd64` or `aarch64`/`arm64` (packages ship for both).
- **CPU/RAM:** 1 vCPU / 512 MB for the service itself; size up for large fleets.
- **Disk:** 500 MB for the binary plus database growth sized to your retention.
- **PostgreSQL:** 14 or newer. The package depends on the PostgreSQL client/server
  but does **not** create a database — you do that in Step 2.
- **Network:**
  - TCP/8443 inbound for the API and UI.
  - TCP/22 outbound from this host to every managed host (Kensa scans over SSH).
- **A browser** to reach the UI, and `sudo`/root for the install steps. The
  service itself runs as the unprivileged `openwatch` user the package creates.

> Download the `.rpm`/`.deb`, the `SHA256SUMS`, `SHA256SUMS.asc`, and `KEYS`
> from the GitHub release. To verify authenticity before installing:
> `gpg --import KEYS && gpg --verify SHA256SUMS.asc SHA256SUMS`, then
> `sha256sum -c SHA256SUMS`. RPMs are also signed in-header — import `KEYS`
> with `rpm --import KEYS` and check with `rpm -K openwatch-*.rpm`.

---

## Install on RHEL family (RPM)

### Step 1 — Install PostgreSQL

```bash
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

### Step 2 — Provision the database

Create the role and database:

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE openwatch WITH LOGIN PASSWORD 'replace-with-a-strong-password';
CREATE DATABASE openwatch OWNER openwatch;
SQL
```

Allow password auth from localhost. Edit `/var/lib/pgsql/data/pg_hba.conf` and
ensure these lines exist near the top of the host rules, then reload:

```
host    openwatch    openwatch    127.0.0.1/32    scram-sha-256
host    openwatch    openwatch    ::1/128         scram-sha-256
```

```bash
sudo systemctl reload postgresql
PGPASSWORD='replace-with-a-strong-password' \
  psql -h 127.0.0.1 -U openwatch -d openwatch -c '\conninfo'
```

### Step 3 — Install the packages

```bash
sudo dnf install -y ./openwatch-0.2.0~rc.8-1.x86_64.rpm ./kensa-rules-0.4.3-1.noarch.rpm
```

Install **both** files in one transaction. `openwatch` declares a hard
dependency on `kensa-rules` — the rule corpus the scan engine loads from
`/usr/share/kensa/rules`. Installing `openwatch` alone fails the dependency
check (by design: a corpus-less node cannot scan). `kensa-rules` is `noarch`
and versioned on the Kensa content line (e.g. `0.4.3`), independent of the
platform version, so the rules can update without re-releasing OpenWatch.

Use the filenames you downloaded (`aarch64` for the arm64 openwatch RPM; the
`kensa-rules` package is the same `noarch` file for every arch). Installing the
packages:

1. Creates the `openwatch` system user and group (idempotent).
2. Installs the binary at `/usr/bin/openwatch`, config under `/etc/openwatch/`
   (`openwatch.toml` plus a self-signed TLS cert/key), the `systemd` unit, and
   the `/var/lib/openwatch` and `/var/log/openwatch` data directories. The
   `kensa-rules` package installs the rule corpus to `/usr/share/kensa/rules`.
3. Generates the identity keys the server requires in production —
   `/etc/openwatch/keys/jwt_private.pem` (RSA-2048 JWT signing key) and
   `/etc/openwatch/keys/credential.key` (AES-256 credential DEK). This is
   generate-if-absent: a reinstall or upgrade never overwrites existing keys
   (regenerating them would invalidate sessions and make stored SSH/MFA
   secrets undecryptable). The server does **not** auto-generate these — it
   exits if they are missing — so the package lays them down at install time.
4. Reloads `systemd`. It does **not** start the service — you do that in Step 7,
   after the database and admin user exist.

Confirm the install:

```bash
rpm -q openwatch
openwatch --version
```

### Step 4 — Configure the database secret

The service reads its database connection string from
`/etc/openwatch/secrets.env` so the password stays out of the world-readable
config. The `systemd` unit loads this file automatically.

```bash
sudo tee /etc/openwatch/secrets.env >/dev/null <<'EOF'
OPENWATCH_DATABASE_DSN=postgres://openwatch:replace-with-a-strong-password@127.0.0.1:5432/openwatch?sslmode=disable
EOF
sudo chown root:openwatch /etc/openwatch/secrets.env
sudo chmod 0640 /etc/openwatch/secrets.env
```

> Use `sslmode=require` (or stronger) for any PostgreSQL that is not on the
> loopback interface.

### Step 5 — Run database migrations

This creates the schema (hosts, scans, transactions, audit events, the job
queue, and more). Run it as the `openwatch` user with the same DSN the service
uses:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch migrate
```

The command applies every pending migration and reports the version it reached.
Re-running it when the schema is current is a safe no-op.

### Step 6 — Create the first admin user

This is the account you sign in with. The admin password policy requires **at
least 15 characters**; pick a single line with no spaces.

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch create-admin --username admin --email admin@example.com
# Type the admin password at the prompt and press Enter.
```

`create-admin` reads the password from stdin when `--password` is omitted, which
keeps it out of your shell history. For automation, pipe it instead:

```bash
printf '%s' "$ADMIN_PASSWORD" | sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch create-admin --username admin --email admin@example.com
```

On success it prints `created admin user admin (admin@example.com) with id=…` and
assigns the built-in `admin` role.

### Step 7 — Start the service

```bash
sudo systemctl enable --now openwatch
sudo systemctl status openwatch
```

### Step 8 — Sign in

Confirm the API is healthy, then open the UI:

```bash
curl -k https://localhost:8443/api/v1/health
# {"status":"healthy","db_connected":true,"version":"<your installed version>"}
```

In a browser, go to **`https://<host>:8443/`**. The browser warns about the
self-signed cert — accept it (or install a CA cert first; see
[Replace the demo TLS cert](#replace-the-demo-tls-cert)) — then sign in with the
admin username and password from Step 6.

The `-k` flag and the browser warning both come from the bundled self-signed
cert. Replace it before any non-loopback use.

---

## Install on Ubuntu and Debian (DEB)

The flow is identical to the RPM path; only Steps 1–3 differ.

### Step 1 — Install PostgreSQL

```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

### Step 2 — Provision the database

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE openwatch WITH LOGIN PASSWORD 'replace-with-a-strong-password';
CREATE DATABASE openwatch OWNER openwatch;
SQL
```

Ubuntu's default `pg_hba.conf` already allows `scram-sha-256` for
`host all all 127.0.0.1/32`, so no edit is needed unless you customized it.
Verify:

```bash
PGPASSWORD='replace-with-a-strong-password' \
  psql -h 127.0.0.1 -U openwatch -d openwatch -c '\conninfo'
```

### Step 3 — Install the packages

```bash
sudo apt install -y ./openwatch_0.2.0~rc.8_amd64.deb ./kensa-rules_0.4.3_all.deb
```

Install **both** files together — `openwatch` `Depends` on `kensa-rules` (the
scan engine's rule corpus at `/usr/share/kensa/rules`), so installing the
openwatch `.deb` alone fails the dependency check by design. The `kensa-rules`
package is `Architecture: all` (one file for every arch). Use the openwatch
filename you downloaded (`arm64` for aarch64). If `apt` reports missing
dependencies, add `-f`. The packages create the `openwatch` user, install the
same files as the RPM plus the corpus, and reload `systemd` without starting
the service.

```bash
dpkg -l openwatch
openwatch --version
```

### Steps 4–8

Follow Steps 4 through 8 from the RPM section above — configure
`/etc/openwatch/secrets.env`, run `openwatch migrate`, run
`openwatch create-admin`, `systemctl enable --now openwatch`, and sign in at
`https://<host>:8443/`. The commands are the same.

---

## First steps as an administrator

Once you are signed in:

1. **Add a host.** Provide the hostname/IP and an SSH credential (key or
   password). OpenWatch checks reachability and discovers the OS.
2. **Confirm the credential.** The host's liveness and intelligence panels
   populate once the credential works.
3. **Run a Kensa scan** and read the compliance posture, then drift and
   exceptions over time.
4. **Add more administrators or scoped roles** from Settings as needed.

For the day-to-day workflows, see the operator guides under
[`docs/guides/`](../guides/) (hosts and remediation, scanning and compliance,
user roles). For the API, see [`api/openapi.yaml`](../../api/openapi.yaml).

---

## Common operations

### Service control

```bash
sudo systemctl start openwatch        # start
sudo systemctl stop openwatch         # stop
sudo systemctl restart openwatch      # restart
sudo systemctl status openwatch       # current state
sudo systemctl enable openwatch       # start at boot
sudo systemctl disable openwatch      # don't start at boot
```

### Logs

The service logs JSON to journald:

```bash
sudo journalctl -u openwatch -f                  # tail live
sudo journalctl -u openwatch --since '5 min ago' # recent
sudo journalctl -u openwatch -o cat | jq .       # pretty-print JSON
```

### Inspect the resolved config

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch check-config
```

### Replace the demo TLS cert

The package ships a self-signed cert. Replace it with one from your CA for any
non-loopback use:

```bash
sudo cp /path/to/your-cert.pem /etc/openwatch/tls/cert.pem
sudo cp /path/to/your-key.pem  /etc/openwatch/tls/key.pem
sudo chown root:openwatch       /etc/openwatch/tls/cert.pem
sudo chown openwatch:openwatch  /etc/openwatch/tls/key.pem
sudo chmod 0644                 /etc/openwatch/tls/cert.pem
sudo chmod 0600                 /etc/openwatch/tls/key.pem
sudo systemctl restart openwatch
```

The server reads the cert on every TLS handshake, so swapping the files takes
effect for new connections without a restart; restart anyway to cover existing
keep-alive connections.

### Configuration layering

Config values resolve in this order, highest precedence first:

1. CLI flags (`--listen`, `--log-level`)
2. Environment variables (`OPENWATCH_<SECTION>_<KEY>`)
3. The TOML file (`/etc/openwatch/openwatch.toml`)
4. Built-in defaults

Recognized environment variables:

| Variable | Effect |
|----------|--------|
| `OPENWATCH_SERVER_LISTEN` | Override `[server].listen` (default `:8443`) |
| `OPENWATCH_SERVER_TLS_CERT` | Override `[server].tls_cert` |
| `OPENWATCH_SERVER_TLS_KEY` | Override `[server].tls_key` |
| `OPENWATCH_DATABASE_DSN` | Override `[database].dsn` |
| `OPENWATCH_DATABASE_MAX_CONNECTIONS` | Override `[database].max_connections` |
| `OPENWATCH_LOGGING_LEVEL` | `debug` / `info` / `warn` / `error` |
| `OPENWATCH_LOGGING_FORMAT` | `json` / `text` |

---

## Troubleshooting

### Service won't start

```bash
sudo systemctl status openwatch
sudo journalctl -u openwatch --since '1 min ago' -p err
```

| Symptom | Cause | Fix |
|---------|-------|-----|
| `config: env override: OPENWATCH_DATABASE_DSN: …` | Malformed DSN in `secrets.env` | Use `postgres://user:pass@host:port/db?sslmode=…` |
| `db: ping: … password authentication failed` | Wrong DSN password, or `pg_hba.conf` rejects scram | Recheck Step 2; reload PostgreSQL after edits |
| `db: ping: … connection refused` | PostgreSQL not running | `sudo systemctl status postgresql` |
| `server: … no such file: cert.pem` | TLS cert path or perms wrong | Ensure `/etc/openwatch/tls/cert.pem` is readable by `openwatch` |

### `migrate` fails

`connection refused` means PostgreSQL isn't running; `password authentication
failed` means the DSN or `pg_hba.conf` is wrong (recheck Step 2).

### Can't sign in

- Confirm you created the admin: re-run `openwatch create-admin` (it reports if
  the username already exists).
- The password must be at least 15 characters and was read as a single line —
  re-create the admin if you're unsure what was stored.
- Make sure you're using `https://` (not `http://`) and accepted the cert.

### Health endpoint returns 503

```bash
curl -k https://localhost:8443/api/v1/health
# {"error":{"code":"server.unavailable",…}}
```

The database ping inside `/health` failed. Check `journalctl -u openwatch` for
the underlying error.

---

## Upgrading

Upgrading is one command. Download the newer `openwatch` package (and the newer
`kensa-rules` package if the rule corpus moved) and install it the same way you
did originally:

```bash
# RHEL family
sudo dnf install -y ./openwatch-<new>.x86_64.rpm ./kensa-rules-<new>.noarch.rpm

# Debian / Ubuntu
sudo apt install -y ./openwatch_<new>_amd64.deb ./kensa-rules_<new>_all.deb
```

On an upgrade (and only on an upgrade — never on a fresh install) the package
post-install step runs the upgrade helper, which:

1. Checks the database is reachable. If it is not, it leaves the service alone,
   prints how to finish later (`openwatch migrate && systemctl restart
   openwatch`), and does **not** fail the package transaction.
2. Stops the service so the old binary never runs against a half-migrated
   schema.
3. Takes a full `pg_dump` restore point into `/var/lib/openwatch/backups/`
   before touching the schema. If the backup fails, it aborts **without**
   migrating (fail-closed) — your data is untouched.
4. Applies any pending migrations, then starts the service again.

If a migration fails, the helper leaves the service **stopped** and exits
non-zero so the package manager surfaces the problem, and it prints the restore
path. Your data is intact (each migration runs in its own transaction and rolls
back on error). After fixing the cause:

```bash
openwatch migrate            # re-apply; reads the same DSN from secrets.env
sudo systemctl start openwatch
```

To preview what an upgrade would apply without changing anything:

```bash
sudo -u openwatch openwatch migrate --status
```

Tunables live in `/etc/openwatch/upgrade.conf` (a `noreplace` config file):
`AUTO_BACKUP=yes|no` toggles the pre-migration dump, and
`BACKUP_RETENTION_DAYS` controls pruning. A `systemd` timer
(`openwatch-backup-cleanup.timer`) prunes old dumps daily but **always keeps the
most recent one** regardless of age.

> Scope: this automates the OpenWatch **application** schema only. A PostgreSQL
> **engine** major-version upgrade (for example PostgreSQL 15 -> 16) is a
> separate, operator-supervised `pg_upgrade` and is never triggered from a
> package scriptlet. See `specs/release/upgrade.spec.yaml` for the full
> contract.

---

## Uninstall

### RPM

```bash
sudo systemctl stop openwatch
sudo dnf remove -y openwatch
```

Config under `/etc/openwatch/` is preserved (`%config(noreplace)`). Remove it
manually if you won't reinstall:

```bash
sudo rm -rf /etc/openwatch /var/lib/openwatch /var/log/openwatch
sudo userdel openwatch && sudo groupdel openwatch
```

### DEB

```bash
sudo systemctl stop openwatch
sudo apt remove openwatch          # leaves /etc/openwatch in place
sudo apt purge openwatch           # also removes the packaged config
```

`apt purge` removes the packaged `openwatch.toml` but leaves `secrets.env` and
the TLS material; remove those manually if needed.

### The database

Removing the package does **not** touch PostgreSQL. To reclaim that space:

```bash
sudo -u postgres psql <<'SQL'
DROP DATABASE openwatch;
DROP ROLE openwatch;
SQL
```

---

## Where to go next

- **Operator guides:** [`docs/guides/`](../guides/) — hosts and remediation,
  scanning and compliance, user roles.
- **API contract:** [`api/openapi.yaml`](../../api/openapi.yaml) — every endpoint
  with its required permission, license gate, and audit events.
- **Behavioral specs:** [`specs/`](../../specs/).
- **Release process:** [`docs/runbooks/RELEASING.md`](../runbooks/RELEASING.md).

---

## Quick reference card

```
UI + API       https://<host>:8443/        (API under /api/v1/…)
TLS cert       /etc/openwatch/tls/{cert,key}.pem   (self-signed by default)
Config         /etc/openwatch/openwatch.toml
DB secret      /etc/openwatch/secrets.env          (OPENWATCH_DATABASE_DSN)
Service unit   /etc/systemd/system/openwatch.service
Binary         /usr/bin/openwatch
Data / logs    /var/lib/openwatch  /var/log/openwatch  (journald is primary)
User/group     openwatch:openwatch
Migrate        sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch migrate
Create admin   sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch create-admin --username admin --email you@example.com
Logs           journalctl -u openwatch -f
Restart        sudo systemctl restart openwatch
```
