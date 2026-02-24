# OpenWatch

**Know whether your servers are compliant — without logging into each one.**

[![License: AGPLv3 + MSE](https://img.shields.io/badge/License-AGPLv3%20%2B%20MSE-blue.svg)](LICENSE)
[![Backend CI](https://github.com/Hanalyx/OpenWatch/actions/workflows/ci.yml/badge.svg)](https://github.com/Hanalyx/OpenWatch/actions/workflows/ci.yml)
[![Documentation](https://img.shields.io/badge/docs-latest-brightgreen)](https://hanalyx.github.io/OpenWatch/)
[![GitHub Discussions](https://img.shields.io/github/discussions/Hanalyx/OpenWatch)](https://github.com/Hanalyx/OpenWatch/discussions)

OpenWatch connects to your Linux servers over SSH, runs 338 compliance checks against STIG, CIS, NIST 800-53, PCI DSS, and FedRAMP baselines, and shows you exactly what's passing, what's failing, and what to fix — all from a single dashboard.

![OpenWatch Host Management Dashboard](docs/images/dashboard-preview.png)

## The Problem

You manage 5, 50, or 500 Linux servers. An auditor asks: *"Are these systems compliant with STIG?"* You don't know. Finding out means SSHing into each one, running checks manually, and assembling spreadsheets. It takes days. Results are stale before you finish.

## What OpenWatch Does

- **Scans your servers automatically** over SSH — no agents to install
- **Checks against real frameworks** — DISA STIG, CIS Benchmarks, NIST 800-53, PCI DSS 4.0, FedRAMP Moderate
- **Shows compliance scores per host** — 73.8%, 69.7%, instantly visible
- **Flags critical issues** — know which servers need attention right now
- **Stores evidence** — every check records what command ran, what it expected, what it found

### How It Compares

| | OpenWatch | Manual Checks | OpenSCAP CLI |
|---|---|---|---|
| Multi-host scanning | One click | SSH into each server | Script it yourself |
| Dashboard & history | Built-in | Spreadsheets | None |
| Framework coverage | STIG + CIS + NIST + PCI + FedRAMP | Whatever you remember | STIG/CIS only |
| Accuracy vs CLI | 72.2% match | Depends on you | 62% (OVAL interpretation gaps) |
| Agents required | No (SSH) | No | No |
| Setup time | 10 minutes | N/A | Hours of scripting |

## Deploy in 10 Minutes

**Requirements:** Docker (or Podman), Linux host, 4GB RAM

```bash
git clone https://github.com/hanalyx/openwatch.git
cd openwatch
./start-openwatch.sh --runtime docker --build
```

Wait ~90 seconds, then open **http://localhost:3000**. Default login: `admin` / `admin`.

**Change the default password immediately.**

### Run Your First Scan

1. **Add credentials** — Settings > System Credentials > add your SSH user/key
2. **Add a host** — Hosts > Add Host > enter IP, select credentials
3. **Scan** — Click the play button on the host card

Results appear in under a minute. No SCAP content to download, no XML to wrangle — OpenWatch ships with 338 built-in Kensa rules.

## Architecture

```
You  -->  OpenWatch UI (React)  -->  OpenWatch API (FastAPI)
                                          |
                                    Kensa Engine (338 YAML rules)
                                          |
                                     SSH to targets
                                          |
                                   Your Linux Servers
```

**Stack:** React 19, FastAPI, PostgreSQL, Redis/Celery, Kensa compliance engine, Docker

## Security

OpenWatch is built for environments where security is the requirement, not an afterthought:

- **AES-256-GCM** encryption for stored credentials
- **RS256 JWT** authentication with Argon2id password hashing
- **FIPS 140-2** compliant cryptography (RHEL 9 validated OpenSSL)
- **RBAC** with 6 roles (Viewer through Superadmin)
- **Audit logging** on all security events
- **No agents** — scans over SSH, nothing installed on targets

Report vulnerabilities to security@hanalyx.com.

## Documentation

| Topic | Link |
|-------|------|
| API Reference | [Swagger UI](http://localhost:8000/api/docs) (when running) |
| Full Documentation | [hanalyx.github.io/OpenWatch](https://hanalyx.github.io/OpenWatch/) |
| First Run Setup | [docs/FIRST_RUN_SETUP.md](docs/FIRST_RUN_SETUP.md) |
| Development Guide | [docs/DEVELOPMENT_WORKFLOW.md](docs/DEVELOPMENT_WORKFLOW.md) |
| Security Audit | [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) |

## Community

Have a question, idea, or want to share how you're using OpenWatch?

**[Join the Discussion](https://github.com/Hanalyx/OpenWatch/discussions)**

- **Q&A** — Get help with setup, scanning, and configuration
- **Ideas** — Propose features and integrations
- **Show and Tell** — Share your compliance workflows

Found a bug? [Open an issue](https://github.com/Hanalyx/OpenWatch/issues/new).

## Contributing

```bash
# Backend
cd backend && pip install -r requirements.txt
pytest tests/ -v

# Frontend
cd frontend && npm install
npm run dev    # http://localhost:3001
npm test
```

See [docs/STOP_BREAKING_THINGS.md](docs/STOP_BREAKING_THINGS.md) before submitting a PR.

## License

**OpenWatch Community License (AGPLv3 + Managed Service Exception)**

- Free to use, modify, and self-host
- Cannot offer as SaaS without a commercial license

See [LICENSE](LICENSE) for details. Commercial licensing: [legal@hanalyx.com](mailto:legal@hanalyx.com)
