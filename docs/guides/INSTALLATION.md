# OpenWatch install guide (native packages)

**Last updated:** 2026-07-31 · **Applies to:** OpenWatch v0.7.0 (Eyrie)

This guide takes an administrator from a fresh Linux host to a running,
logged-in OpenWatch. Install the packages and run `openwatch setup`, which does
the rest. The manual procedure that follows documents every step `setup`
performs, for operators who need to stage the work themselves.

## What you get

Installing the package gives you a single `systemd`-managed service that serves
both the REST API and the web UI over HTTPS on port 8443. One binary contains
everything: the API, the embedded React UI, and the Kensa compliance engine; no
separate web tier, no container runtime, no external cache.

After the steps below you have:

- The OpenWatch UI and API at `https://<host>:8443/`, behind session login.
- An `admin` account you create during install.
- A PostgreSQL database holding hosts, scans, transactions, and audit events.
- Kensa ready to run SSH-based compliance checks against the hosts you add.

---

## At a glance

Install the packages, then run `openwatch setup`:

```bash
sudo dnf install -y ./openwatch-*.rpm ./kensa-rules-*.noarch.rpm
sudo openwatch setup
```

`setup` provisions PostgreSQL, creates the role and database, writes the
connection string, applies migrations, creates your first administrator, opens
the firewall port, starts the service, and confirms the API answers. It shows
you the whole plan and waits for confirmation before changing anything.

**This is the supported way to install OpenWatch.** The
[manual procedure](#manual-installation-rhel-family-rpm) documents every step
`setup` performs, for operators who need to stage the work differently, satisfy
a change-control process, or integrate with existing configuration management.
Both paths reach the same result.

On a host that already runs PostgreSQL, either takes about five minutes.

---

## Requirements

- **OS:**
  - RPM: RHEL 9, Rocky Linux 9, AlmaLinux 9, Oracle Linux 9, CentOS Stream 9
    (binary-compatible rebuilds; CI smoke-tests the RPM in `rockylinux:9` and
    `almalinux:9` containers, not CentOS Stream 9)
  - DEB: Ubuntu 24.04 LTS, Debian 12 (or a compatible `systemd` derivative)
- **Architecture:** `x86_64`/`amd64` or `aarch64`/`arm64` (packages ship for both).
- **CPU/RAM:** 1 vCPU / 512 MB for the service itself; size up for large fleets.
- **Disk:** 500 MB for the binary plus database growth sized to your retention.
- **PostgreSQL:** 15 or newer. The package depends on the PostgreSQL
  client/server but does **not** create a database. You do that in Step 2.
  PostgreSQL 14 reaches end of life in November 2026, within this release's
  service life, so it is not a supported target for a new install. RHEL 9
  defaults to PostgreSQL 13 and needs a newer module stream enabled: see Step 1.
- **Network:**
  - TCP/8443 inbound for the API and UI.
  - TCP/22 outbound from this host to every managed host (Kensa scans over SSH).
- **A browser** to reach the UI, and `sudo`/root for the install steps. The
  service itself runs as the unprivileged `openwatch` user the package creates.

> Download the `.rpm`/`.deb`, the `SHA256SUMS`, `SHA256SUMS.asc`, and `KEYS`
> from the GitHub release. To verify authenticity before installing:
> `gpg --import KEYS && gpg --verify SHA256SUMS.asc SHA256SUMS`, then
> `sha256sum -c SHA256SUMS`. RPMs are also signed in-header. Import `KEYS`
> with `rpm --import KEYS` and check with `rpm -K openwatch-*.rpm`.

---

## Install with `openwatch setup`

### Step 1: Install the packages

```bash
sudo dnf install -y ./openwatch-*.x86_64.rpm ./kensa-rules-*.noarch.rpm
```

On Debian and Ubuntu:

```bash
sudo apt install -y ./openwatch_*_amd64.deb ./kensa-rules_*_all.deb
```

Install **both** files in one transaction. `openwatch` depends on `kensa-rules`,
the rule corpus the scan engine loads. The packages do not start the service:
`setup` does that once the database exists.

`setup` ships inside the `openwatch` package, so this step comes first. It
configures OpenWatch; it does not install it.

### Step 2: Run setup

```bash
sudo openwatch setup
```

It detects the host, prints a plan, and waits:

```
OpenWatch setup: rhel 9.8 (amd64)

Preflight
  [ok  ] running as root
  [ok  ] platform rhel 9.8 (amd64)
           tested
  [ok  ] openwatch binary installed
  [ok  ] port 8443 available
  [ok  ] fapolicyd is active
  [ok  ] SELinux enforcing

Plan
   1. install PostgreSQL (dnf install postgresql-server postgresql-contrib)
   2. initialise the data directory and enable postgresql
   3. verify PostgreSQL >= 13 (supported >= 15)
   4. create role "openwatch" with a generated password, hashed scram-sha-256
   5. create database "openwatch" owned by "openwatch"
   6. check pg_hba.conf for the required host rules
   7. write /etc/openwatch/secrets.env with the database DSN
   8. apply database migrations
   9. create the first admin user "admin"
  10. allow inbound 8443/tcp through the host firewall
  11. enable and start openwatch.service
  12. confirm the API answers on https://0.0.0.0:8443/api/v1/health
```

Guided mode asks about the database, the service and the administrator in turn,
with the detected values filled in. Press Enter to accept a section, or `e` to
edit it. Nothing is written until you confirm the plan.

It finishes by proving the install rather than declaring it done:

```
Done.

  URL       https://192.168.1.251:8443/
  Admin     admin <admin@example.com>
  Database  openwatch@127.0.0.1:5432/openwatch

  Changed:
    postgres-install install postgresql
    postgres-cluster initdb /var/lib/pgsql/data
    database-role  create role openwatch
    database       create database openwatch
    secrets-env    write /etc/openwatch/secrets.env
    firewall       allow 8443/tcp
    service        enable --now openwatch.service

  Receipt: /var/lib/openwatch/setup-receipt.json
```

### Step 3: Sign in

Open **`https://<host>:8443/`** and sign in with the administrator you created.
The browser warns about the bundled self-signed certificate; accept it, or
[replace the certificate](#replace-the-demo-tls-cert) first.

---

## How `openwatch setup` behaves

### Running it again is safe

Every step checks whether it is already satisfied before acting, and reports
what it skipped. The usual moment to run an installer is after a previous
attempt stopped part-way, so re-running is the intended recovery: fix whatever
blocked it and run the same command again.

Re-running does **not** rotate the database password. It is recovered from
`/etc/openwatch/secrets.env` so the role and the connection string stay in
agreement.

### It will not edit `pg_hba.conf` unless you ask

PostgreSQL decides who may connect using `pg_hba.conf`, and editing it wrongly
is the most effective way to lock yourself out of your own database. By default
`setup` reports what is missing, prints the exact lines, and stops with exit
code 3:

```
Setup paused: pg_hba.conf needs the rules above before the database role can
authenticate
Everything before this step is done. Complete the manual step above,
then run `openwatch setup` again to continue from here.
```

Add the lines, reload PostgreSQL, and run `setup` again. It resumes from where
it stopped.

To have `setup` do it, pass `--manage-pg-hba`. It then backs the file up,
inserts its rules **above** the existing ones, reloads PostgreSQL, and restores
the original file if the reload fails. The ordering matters: `pg_hba.conf` is
first-match-wins, and the stock RHEL file matches `127.0.0.1/32` with `ident`
before anything appended to the end would be reached.

### It opens the listen port

An active `firewalld` is reconfigured to allow the listen port, because the
health check runs over loopback where the firewall does not apply. Without this
step an install can report itself healthy while being unreachable from every
other machine. Pass `--no-firewall` to decline; `setup` then prints the commands
to open it later and says the service will only be reachable from the host
itself.

`ufw` on Debian and Ubuntu is **not** configured. Open the port yourself.

### Platforms it will run on

| Platform | Behaviour |
|---|---|
| RHEL 9, AlmaLinux 10, Debian 12, Ubuntu 24.04 | Runs. Covered by testing. |
| Rocky, Oracle Linux 8-10, AlmaLinux 8-9, RHEL 10 | Requires `--allow-untested` |
| Ubuntu 22.04, other Debian releases | Requires `--allow-untested` |
| Anything else | Refused |

`untested` means the code recognises the layout and is expected to work, but it
is not covered by automated testing. It runs with `--allow-untested`; please
report the result.

Ubuntu is matched on the full version rather than the major. 24.04 is covered;
24.10 is a different release and is not.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Finished; the API answered and reported a database connection |
| 1 | Failed. Nothing after the failing step ran |
| 3 | Paused for a manual step. Complete it and re-run |

### The receipt

Every applied run writes `/var/lib/openwatch/setup-receipt.json`: the platform,
the resolved plan, every change with the path of any backup taken, and the URL.
It records **where** each credential came from, never the credential, so it is
safe to attach to a ticket.

### Options

| Option | Effect |
|---|---|
| `--dry-run` | Print the plan and change nothing |
| `--yes` | Accept every default without prompting |
| `--plan <file>` | Apply a saved plan; implies non-interactive |
| `--save-plan <file>` | Write the resolved plan and exit without applying |
| `--allow-untested` | Proceed on a platform not covered by testing |
| `--manage-pg-hba` | Let `setup` edit `pg_hba.conf` |
| `--no-firewall` | Do not open the listen port |
| `--db-mode provision\|existing` | Provision PostgreSQL, or use one that already runs |
| `--db-host`, `--db-port`, `--db-name`, `--db-role` | Database connection and names |
| `--listen-port` | HTTPS port (default 8443) |
| `--admin-username`, `--admin-email` | First administrator |
| `--admin-password-from`, `--db-password-from` | `generate`, `prompt`, `env:NAME`, or `file:PATH` |

There is deliberately no `--password` option: a password on the command line is
visible in the process table and lands in shell history. Use `env:NAME` or
`file:PATH`.

### Using a database you already run

```bash
sudo openwatch setup --db-mode existing --db-host db.internal --db-port 5432
```

`setup` then validates rather than provisions: it checks the server is
reachable and supported, and creates the role and database only if they are
missing. It never installs or initialises a remote PostgreSQL.

A non-loopback host requires TLS. `sslmode` is raised off `disable`
automatically, and a plan that sets it back is rejected.

### Unattended and repeated installs

Capture the answers once, apply them anywhere:

```bash
sudo openwatch setup --save-plan /root/openwatch-plan.yaml
sudo openwatch setup --plan /root/openwatch-plan.yaml --admin-password-from env:OW_ADMIN_PW
```

The plan file holds no secrets, so it is safe to commit to configuration
management. The platform is re-detected on every apply and a plan captured on
one distribution is refused on another.

---

## Manual installation: RHEL family (RPM)

Everything below is what `openwatch setup` performs. Use it when you need to
stage the steps separately, when a change-control process requires each action
to be recorded individually, or when integrating with existing configuration
management.

The result is identical. If you are not sure which to use, use `setup`.

### Step 1: Install PostgreSQL

**Check which version your distribution offers before installing.** RHEL 9
defaults to PostgreSQL 13, which is below the supported minimum:

```bash
dnf module list postgresql
```

If the default stream is 14 or lower, enable a stream of 15 or newer first.
Substitute the highest stream your release offers:

```bash
sudo dnf module enable -y postgresql:16
```

Then install, initialise, and start:

```bash
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

Confirm you got what you expected before continuing:

```bash
psql --version
```

If this reports 14 or lower, go back and enable a newer stream. Continuing puts
you on a version this release does not support, and the symptom appears several
steps later as an authentication failure rather than a version error.

### Step 2: Provision the database

Create the role and database:

```bash
sudo -u postgres psql -c "SET password_encryption = 'scram-sha-256'; CREATE ROLE openwatch WITH LOGIN PASSWORD 'replace-with-a-strong-password'"
sudo -u postgres psql -c "CREATE DATABASE openwatch OWNER openwatch"
```

Setting `password_encryption` explicitly is deliberate. `CREATE ROLE` otherwise
hashes the password using whatever the server default happens to be, and that
default changed from `md5` to `scram-sha-256` in PostgreSQL 14. On an older
server the password is stored as an md5 hash while the `pg_hba.conf` rules below
require `scram-sha-256`, and the two can never match. Setting it in the same
session makes this step behave identically on every supported version.

Each statement reports its own `CREATE ROLE` or `CREATE DATABASE`, so you can
see which one succeeded. `could not change directory to "/root"` is harmless:
the `postgres` user cannot read root's working directory, and the command still
runs. Run these from a directory `postgres` can read, such as `/tmp`, to silence
it.

Confirm the password was stored in the expected format:

```bash
sudo -u postgres psql -c "SELECT rolname, substring(rolpassword,1,13) AS stored_as FROM pg_authid WHERE rolname='openwatch'"
```

This must report `SCRAM-SHA-256`. If it reports `md5`, the `SET` did not take
effect; re-run it as `ALTER ROLE openwatch PASSWORD '...'` in the same session
as the `SET`.

Allow password auth from localhost. Edit `/var/lib/pgsql/data/pg_hba.conf` and
ensure these lines exist near the top of the host rules, then reload:

```
host    openwatch    openwatch    127.0.0.1/32    scram-sha-256
host    openwatch    openwatch    ::1/128         scram-sha-256
```

```bash
sudo systemctl reload postgresql
PGPASSWORD='replace-with-a-strong-password' psql -h 127.0.0.1 -U openwatch -d openwatch -c '\conninfo'
```

### Step 3: Install the packages

```bash
sudo dnf install -y ./openwatch-*.x86_64.rpm ./kensa-rules-*.noarch.rpm
```

Install **both** files in one transaction. `openwatch` declares a hard
dependency on `kensa-rules`: the rule corpus the scan engine loads from
`/usr/share/kensa/rules`. Installing `openwatch` alone fails the dependency
check (by design: a corpus-less node cannot scan). `kensa-rules` is `noarch`
and versioned on the Kensa content line (for example `0.8.0`), independent of the
platform version, so the rules can update without re-releasing OpenWatch.

Use the filenames you downloaded (`aarch64` for the arm64 openwatch RPM; the
`kensa-rules` package is the same `noarch` file for every arch). Installing the
packages:

1. Creates the `openwatch` system user and group (idempotent).
2. Installs the binary at `/usr/bin/openwatch`, config under `/etc/openwatch/`
   (`openwatch.toml` plus a self-signed TLS cert/key), the `systemd` unit, and
   the `/var/lib/openwatch` and `/var/log/openwatch` data directories. The
   `kensa-rules` package installs the rule corpus to `/usr/share/kensa/rules`.
3. Generates the identity keys the server requires in production:    `/etc/openwatch/keys/jwt_private.pem` (RSA-2048 JWT signing key) and
   `/etc/openwatch/keys/credential.key` (AES-256 credential DEK). This is
   generate-if-absent: a reinstall or upgrade never overwrites existing keys
   (regenerating them would invalidate sessions and make stored SSH/MFA
   secrets undecryptable). The server does **not** auto-generate these. It
   exits if they are missing: so the package lays them down at install time.
4. Reloads `systemd`. It does **not** start the service. You do that in Step 7,
   after the database and admin user exist.

Confirm the install:

```bash
rpm -q openwatch
openwatch --version
```

### Step 4: Configure the database secret

The service reads its database connection string from
`/etc/openwatch/secrets.env` so the password stays out of the world-readable
config. The `systemd` unit loads this file automatically.

```bash
echo 'OPENWATCH_DATABASE_DSN=postgres://openwatch:replace-with-a-strong-password@127.0.0.1:5432/openwatch?sslmode=disable' | sudo tee /etc/openwatch/secrets.env >/dev/null
sudo chown root:openwatch /etc/openwatch/secrets.env
sudo chmod 0640 /etc/openwatch/secrets.env
```

> **Percent-encode any reserved character in the password.** The DSN is a URI,
> so a password containing one of these characters must be encoded, or the
> connection string parses into something other than what you typed:
>
> | Character | Encode as |
> |---|---|
> | `@` | `%40` |
> | `:` | `%3A` |
> | `/` | `%2F` |
> | `?` | `%3F` |
> | `#` | `%23` |
> | `[` | `%5B` |
> | `]` | `%5D` |
> | `%` | `%25` |
>
> A password of `p@ss@word` becomes
> `postgres://openwatch:p%40ss%40word@127.0.0.1:5432/openwatch?sslmode=disable`.
> Encode only the password. The `@` that separates the credentials from the host
> stays literal, and encoding a character that did not need it is harmless.
>
> This is worth care because it rarely fails as a parse error. An unencoded `@`
> splits the URI at the wrong place and the result still looks like a valid DSN,
> so the error you get points somewhere else. Depending on where the character
> falls you will see either `password authentication failed for user
> "openwatch"`, which points at the role, or a host resolution failure naming a
> host built from part of your password. Step 5 below is the first command to
> use this DSN, so that is where a bad encoding surfaces.

> Use `sslmode=require` (or stronger) for any PostgreSQL that is not on the
> loopback interface.

### Step 5: Run database migrations

This creates the schema (hosts, scans, transactions, audit events, the job
queue, and more). Run it as the `openwatch` user with the same DSN the service
uses:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch migrate
```

The command applies every pending migration and reports the version it reached.
Re-running it when the schema is current is a safe no-op.

### Step 6: Create the first admin user

This is the account you sign in with. The admin password policy requires **at
least 15 characters**; pick a single line with no spaces.

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch create-admin --username admin --email admin@example.com
# Type the admin password at the prompt and press Enter.
```

`create-admin` reads the password from stdin when `--password` is omitted, which
keeps it out of your shell history. Note that the interactive prompt does not
mask input: the characters you type are echoed to the terminal. Run it where the
screen is not observed or recorded, or pipe the password in. For automation,
pipe it instead:

```bash
printf '%s' "$ADMIN_PASSWORD" | sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch create-admin --username admin --email admin@example.com
```

On success it prints `created admin user admin (admin@example.com) with id=…` and
assigns the built-in `admin` role.

### Step 7: Allow the port through the firewall

RHEL enables `firewalld` by default with no ports open, so the service would be
reachable only from the host itself. Skipping this step is easy to miss: the
health check in Step 9 runs over loopback, where the firewall does not apply, so
a fully blocked host looks identical to a working one until someone tries the
URL from another machine.

```bash
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports
```

Skip this only if the host has no firewall, or if OpenWatch is reached through a
reverse proxy on the same machine.

### Step 8: Start the service

```bash
sudo systemctl enable --now openwatch
sudo systemctl status openwatch
```

### Step 9: Sign in

Confirm the API is healthy:

```bash
curl -k https://localhost:8443/api/v1/health
# {"status":"healthy","db_connected":true,"version":"<your installed version>"}
```

That proves the service is serving and reached its database. It does **not**
prove anyone else can reach it, because loopback traffic bypasses the firewall.
Confirm that separately, from a different machine:

```bash
curl -k https://<host>:8443/api/v1/health
```

If this hangs or reports `No route to host`, the firewall is still closed;
revisit Step 7.

In a browser, go to **`https://<host>:8443/`**. The browser warns about the
self-signed cert: accept it (or install a CA cert first; see
[Replace the demo TLS cert](#replace-the-demo-tls-cert)): then sign in with the
admin username and password from Step 6.

The `-k` flag and the browser warning both come from the bundled self-signed
cert. Replace it before any non-loopback use.

---

## Manual installation: Ubuntu and Debian (DEB)

The flow is identical to the RPM path; only Steps 1–3 differ.

### Step 1: Install PostgreSQL

```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

Ubuntu 24.04 ships PostgreSQL 16 and Debian 12 ships 15, so the default package
is already at or above the supported minimum and no pinning is needed. Confirm
anyway, since this is the check that catches an older or customised base image:

```bash
psql --version
```

If it reports 14 or lower, install a newer version from the PostgreSQL APT
repository before continuing.

### Step 2: Provision the database

```bash
sudo -u postgres psql -c "SET password_encryption = 'scram-sha-256'; CREATE ROLE openwatch WITH LOGIN PASSWORD 'replace-with-a-strong-password'"
sudo -u postgres psql -c "CREATE DATABASE openwatch OWNER openwatch"
```

`password_encryption` is set explicitly for the same reason as the RPM path: it
makes the stored hash format independent of the server default, which differs
between PostgreSQL versions.

Ubuntu's default `pg_hba.conf` already allows `scram-sha-256` for
`host all all 127.0.0.1/32`, so no edit is needed unless you customized it.
Verify:

```bash
PGPASSWORD='replace-with-a-strong-password' psql -h 127.0.0.1 -U openwatch -d openwatch -c '\conninfo'
```

### Step 3: Install the packages

```bash
sudo apt install -y ./openwatch_*_amd64.deb ./kensa-rules_*_all.deb
```

Install **both** files together: `openwatch` `Depends` on `kensa-rules` (the
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

### Steps 4-9

Follow Steps 4 through 9 from the RPM section above: configure
`/etc/openwatch/secrets.env`, run `openwatch migrate`, run
`openwatch create-admin`, open the firewall port, `systemctl enable --now
openwatch`, and sign in at `https://<host>:8443/`. The commands are the same
with one exception.

**The firewall step differs.** Debian and Ubuntu use `ufw`, which is inactive
on a default install and needs no action. Check before assuming:

```bash
sudo ufw status
```

If it reports `Status: active`, allow the port:

```bash
sudo ufw allow 8443/tcp
```

As on RHEL, confirm from another machine rather than from the host, since
loopback traffic bypasses the firewall entirely.

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

For the day-to-day workflows, see [Hosts and remediation](HOSTS_AND_REMEDIATION.md),
[Scanning and compliance](SCANNING_AND_COMPLIANCE.md), and [User roles](USER_ROLES.md).

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
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch check-config
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
| `OPENWATCH_SERVER_LISTEN` | Override `[server].listen` (default `0.0.0.0:8443`) |
| `OPENWATCH_SERVER_TLS_CERT` | Override `[server].tls_cert` |
| `OPENWATCH_SERVER_TLS_KEY` | Override `[server].tls_key` |
| `OPENWATCH_DATABASE_DSN` | Override `[database].dsn` |
| `OPENWATCH_DATABASE_MAX_CONNECTIONS` | Override `[database].max_connections` |
| `OPENWATCH_LOGGING_LEVEL` | `debug` / `info` / `warn` / `error` |
| `OPENWATCH_LOGGING_FORMAT` | `json` / `text` |

---

## Troubleshooting

### `setup` stopped and said "Setup paused"

Not a failure. `setup` reached a step it will not perform without you: by
default that is `pg_hba.conf`. Everything before it is done. Complete the
printed step and run `openwatch setup` again; it resumes from there. Exit code
is 3.

### `setup` says the platform is not covered by testing

The distribution is recognised and expected to work, but is not covered by
automated testing. Re-run with `--allow-untested`. If it reports the platform
as unsupported instead, `setup` does not know that distribution's PostgreSQL
layout and will not guess; use the manual procedure.

### `setup` reports PostgreSQL is too old

The server is below the minimum of 13. On RHEL, the default stream is older
than the supported version; enable a newer one and reinstall PostgreSQL:

```bash
dnf module list postgresql
sudo dnf module enable -y postgresql:16
```

### `setup` says PostgreSQL refuses local superuser connections

`pg_hba.conf` has no rule for local connections by the `postgres` user, so
`setup` cannot inspect the server at all. This usually follows a hand-edit that
replaced the file's default rules instead of adding to them. Add

```
local   all   all   peer
```

above the other rules, run `sudo systemctl reload postgresql`, and run `setup`
again.

### The install finished but nobody can reach it

The health check runs over loopback, where the firewall does not apply, so a
blocked host still reports healthy. Check from another machine:

```bash
curl -k https://<host>:8443/api/v1/health
```

`No route to host` or a hang means the firewall is closed:

```bash
sudo firewall-cmd --list-ports          # RHEL family
sudo firewall-cmd --permanent --add-port=8443/tcp && sudo firewall-cmd --reload
sudo ufw status                         # Debian family
```

Also confirm the service is not bound to loopback only:

```bash
sudo ss -tlnp | grep 8443               # want *:8443, not 127.0.0.1:8443
```

### Service won't start

```bash
sudo systemctl status openwatch
sudo journalctl -u openwatch --since '1 min ago' -p err
```

| Symptom | Cause | Fix |
|---------|-------|-----|
| `database.dsn: scheme "" must be postgres:// or postgresql://` | Malformed DSN in `secrets.env` | Use `postgres://user:pass@host:port/db?sslmode=…` |
| `db: ping: … password authentication failed` | Wrong DSN password, or `pg_hba.conf` rejects scram | Recheck Step 2; reload PostgreSQL after edits. If the password contains a reserved character, confirm it is percent-encoded in the DSN |
| `db: ping: … Ident authentication failed` | A catch-all `pg_hba.conf` rule matches before yours | `pg_hba.conf` is first-match-wins: move the OpenWatch rules **above** any `host all all` line, then reload |
| `db: ping: … connection refused` | PostgreSQL not running | `sudo systemctl status postgresql` |
| `server: … no such file: cert.pem` | TLS cert path or perms wrong | Ensure `/etc/openwatch/tls/cert.pem` is readable by `openwatch` |

### `migrate` fails

`connection refused` means PostgreSQL isn't running; `password authentication
failed` means the DSN or `pg_hba.conf` is wrong (recheck Step 2).

### Can't sign in

- Confirm you created the admin: re-run `openwatch create-admin` (it reports if
  the username already exists).
- The password must be at least 15 characters and was read as a single line:   re-create the admin if you're unsure what was stored.
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

On an upgrade (and only on an upgrade: never on a fresh install) the package
post-install step runs the upgrade helper, which:

1. Checks the database is reachable. If it is not, it leaves the service alone,
   prints how to finish later (`openwatch migrate && systemctl restart
   openwatch`), and does **not** fail the package transaction.
2. Stops the service so the old binary never runs against a half-migrated
   schema.
3. Takes a full `pg_dump` restore point into `/var/lib/openwatch/backups/`
   before touching the schema. If the backup fails, it aborts **without**
   migrating (fail-closed). Your data is untouched.
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
> package scriptlet.

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
sudo -u postgres psql -c "DROP DATABASE openwatch"
sudo -u postgres psql -c "DROP ROLE openwatch"
```

---

## Where to go next

- **Operator guides:** [Hosts and remediation](HOSTS_AND_REMEDIATION.md),
  [Scanning and compliance](SCANNING_AND_COMPLIANCE.md), [User roles](USER_ROLES.md).
- **API contract:** [API guide](API_GUIDE.md): every endpoint with its required
  permission, license gate, and audit events.

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
Install        sudo openwatch setup                (--dry-run to preview)
Re-run         sudo openwatch setup                (idempotent; resumes)
Receipt        /var/lib/openwatch/setup-receipt.json
Migrate        sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch migrate
Create admin   sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch create-admin --username admin --email you@example.com
Logs           journalctl -u openwatch -f
Restart        sudo systemctl restart openwatch
Open port      sudo firewall-cmd --permanent --add-port=8443/tcp && sudo firewall-cmd --reload
Check remotely curl -k https://<host>:8443/api/v1/health   (from ANOTHER machine)
```
