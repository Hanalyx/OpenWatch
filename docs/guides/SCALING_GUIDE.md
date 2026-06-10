# Scaling guide

This guide covers how OpenWatch behaves as you add hosts, run more scans, and
push more concurrent API traffic, and what you can tune today. It describes the
current Go-era stack: a single `openwatch` binary that serves the REST API and
the embedded React UI over HTTPS on port `8443`, backed by PostgreSQL, with the
Kensa compliance engine built in. There is no separate web tier, no container
runtime, no Redis, and no Celery.

For first-time install and configuration, follow
`docs/engineering/install_guide.md` — this guide assumes a working install and
focuses only on capacity and tuning.

## What scales, and how

OpenWatch has two long-lived processes and one database:

| Component | What it does | How you scale it today |
|-----------|--------------|------------------------|
| `openwatch serve` | HTTPS API + embedded UI + in-process schedulers (liveness, intelligence, discovery) | Vertical: more CPU/RAM on the host. The process is stateless apart from PostgreSQL, so horizontal API replicas are possible in principle but not yet packaged (see "Not yet implemented"). |
| `openwatch worker` | Drains the PostgreSQL scan-job queue and runs Kensa scans over SSH | Run more `openwatch worker` processes against the same database. The queue uses `SELECT ... FOR UPDATE SKIP LOCKED`, so multiple workers cooperate without double-claiming a job. |
| PostgreSQL | All state: hosts, scans, transactions, audit events, queue | Vertical first (CPU, RAM, faster disk), then tune `max_connections` and the OpenWatch pool size. |

The scan worker is a separate process from the API server. `openwatch serve`
runs the liveness, intelligence, and discovery schedulers in-process, but it
does **not** drain the scan-job queue. You must run `openwatch worker`
separately for scans to execute. Verify the split in `cmd/openwatch/main.go`
(`cmdServe`) and `cmd/openwatch/worker.go` (`cmdWorker`).

## Scaling the scan workers

Scans are the most resource-intensive work OpenWatch does: each one opens an SSH
session to a target host and runs Kensa's native YAML checks. Worker throughput
is the usual first bottleneck.

### Run more worker processes

The scan queue is PostgreSQL-native and claims one job at a time per worker with
`SKIP LOCKED`. To increase scan throughput, run additional `openwatch worker`
processes pointed at the same database and config:

```bash
openwatch worker --config /etc/openwatch/openwatch.toml
```

Each worker claims one scan job at a time (`internal/worker/scan_worker.go`).
Within a single worker, a per-host `pg_advisory_xact_lock` serializes work so
two jobs for the same host never run concurrently. Across workers, the queue's
`SKIP LOCKED` semantics prevent any two workers from claiming the same job.

The package ships only the `openwatch.service` unit, which runs `serve`
(`packaging/common/openwatch.service`). There is no packaged worker unit yet, so
run the worker under your own `systemd` unit or process supervisor. A minimal
unit mirrors the shipped one but changes the `ExecStart` command:

```ini
[Unit]
Description=OpenWatch scan worker
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=openwatch
Group=openwatch
EnvironmentFile=-/etc/openwatch/secrets.env
ExecStart=/usr/bin/openwatch worker --config /etc/openwatch/openwatch.toml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Use a systemd template (for example `openwatch-worker@.service`) if you want to
run several workers on one host. The worker shares the same configuration,
database DSN, JWT key, and credential key as `serve`, so no extra config is
required.

### Poll interval

Each worker sleeps between dequeue attempts when the queue is empty. The
`--poll-interval` flag controls this; it defaults to `1s` and is capped at `5s`
(`internal/worker/scan_worker.go`, `DefaultPollInterval` / `MaxPollInterval`):

```bash
openwatch worker --poll-interval 2s
```

A shorter interval lowers scan-pickup latency on an idle queue at the cost of
more empty database round-trips. A longer interval does the reverse. The cap
exists because raising it further only adds latency without a corresponding
benefit. Worker concurrency comes from running more processes, not from a
per-worker concurrency knob — there is no `--concurrency` flag.

## Scaling PostgreSQL

PostgreSQL holds all OpenWatch state and is the shared coordination point for
the queue. Tune it before reaching for anything else.

### Connection pool

OpenWatch opens one pgx pool per process (`internal/db/db.go`,
`db.NewPool`). The pool size is the `max_connections` value under `[database]`
in `/etc/openwatch/openwatch.toml`; it defaults to `25`
(`packaging/common/openwatch.toml`, `internal/config/config.go`):

```toml
[database]
dsn             = "postgres://openwatch@localhost/openwatch?sslmode=require"
max_connections = 25
```

You can also override it with the environment variable
`OPENWATCH_DATABASE_MAX_CONNECTIONS` (set it in `/etc/openwatch/secrets.env` or
the unit's `EnvironmentFile`). Each running process — `serve` and every
`worker` — opens its own pool of up to `max_connections`. Size PostgreSQL's
server-side `max_connections` to cover the sum across all OpenWatch processes
plus headroom for `psql`, backups, and monitoring. As a rule of thumb:

```
postgres max_connections  >=  (1 serve + N workers) * openwatch max_connections + slack
```

### Server tuning

Standard PostgreSQL tuning applies; OpenWatch does nothing unusual here. Start
from your host's RAM and adjust `shared_buffers`, `effective_cache_size`,
`work_mem`, and `max_wal_size` to match. Keep the database on fast local or
network-attached SSD storage — the transaction log and audit-event tables are
the highest-write paths.

### Migrations

Schema changes ship as ordered migrations in `internal/db/migrations/`, applied
with `openwatch migrate`. Run migrations once per upgrade against a single
database before starting the new binary; the command is safe to re-run and
reports the resulting version. Multiple processes can then connect to the
already-migrated schema.

## Capacity planning

OpenWatch has no fixed sizing matrix, and the scan cadence — not raw host
count — drives load. The intelligence and liveness schedulers run on
operator-tunable intervals, and scans are enqueued on a per-host schedule, so a
large fleet scanned infrequently can be lighter than a small fleet scanned
aggressively.

Plan capacity from these levers rather than a host-count table:

- **Scan throughput** — add `openwatch worker` processes until the scan queue
  drains as fast as you enqueue. Watch for jobs sitting in the queue.
- **API/UI responsiveness** — give the `serve` host enough CPU and RAM; it is a
  single process today, so vertical sizing is the lever.
- **PostgreSQL** — size RAM and connections to the combined pool demand above;
  this is usually the first thing to upgrade for a large fleet.

Measure on your own workload before committing hardware. The numbers that matter
are queue depth, scan duration, API latency, and PostgreSQL connection count and
query latency — all observable with the tools below.

## Observing load

There is no Prometheus endpoint and no Grafana stack in the current build (see
"Not yet implemented"). What you have today:

- **Health** — `GET /api/v1/health` returns `200` when the service and its
  database connection are healthy, `503` when degraded
  (`api/openapi.yaml`, `internal/server/handlers.go`). Use it for load-balancer
  and uptime probes.
- **Version** — `GET /api/v1/version` returns build metadata
  (`api/openapi.yaml`). `openwatch --version` prints the same locally.
- **Logs** — both processes emit structured JSON logs to `journald`. Follow them
  with `journalctl`:

  ```bash
  journalctl -u openwatch -f
  ```

  The worker logs a periodic `worker.loop.tick` line (roughly every 60s) with
  idle/claimed/in-flight/completed counters — a lightweight way to confirm a
  worker is alive and draining (`internal/worker/scan_worker.go`).
- **Audit and queue state** — query PostgreSQL directly:

  ```bash
  psql "$OPENWATCH_DATABASE_DSN" -c \
    "SELECT status, count(*) FROM job_queue GROUP BY status;"
  ```

  A growing count of non-terminal jobs means workers are not keeping up; add
  worker processes.

## Not yet implemented

Be explicit about what this stack does *not* offer today, so you do not plan
around features that are absent:

- **Horizontal API scaling is not packaged.** The `serve` process is stateless
  apart from PostgreSQL (it uses stateless JWT auth), so running replicas behind
  a load balancer is architecturally possible, but there is no shipped unit,
  load-balancer config, or supported procedure for it. Treat `serve` as a single
  vertically-scaled process for now.
- **No packaged worker unit.** Only `openwatch.service` (running `serve`) ships
  in the RPM/DEB. Running additional scan workers requires the operator-authored
  unit shown above.
- **No Prometheus/Grafana/metrics endpoint.** There is no `/metrics` route and
  no bundled monitoring stack. Observability is `GET /api/v1/health`, the JSON
  logs in `journald`, and direct PostgreSQL queries.
- **No PgBouncer integration, read replicas, or built-in connection proxy.** You
  can place standard PostgreSQL tooling in front of the database yourself;
  OpenWatch only knows the single DSN it is configured with.
- **No Redis, Celery, or message broker.** Background work is the PostgreSQL
  `SKIP LOCKED` queue only. Anything that referenced these in older docs is from
  the archived Python stack and does not apply.

## Related documentation

| Topic | Document |
|-------|----------|
| Install and configuration | `docs/engineering/install_guide.md` |
| Roles and permissions | `docs/engineering/rbac_registry.md` |
| Kensa scanning boundary | `docs/KENSA_OPENWATCH_BOUNDARY.md` |
| API contract | `api/openapi.yaml` (paths under `/api/v1`) |
| Worker behavior spec | `specs/system/worker-subcommand.spec.yaml` |
