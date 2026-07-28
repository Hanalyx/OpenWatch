# Security Policy

## Reporting a vulnerability

Email **security@hanalyx.com**. Do not open a public issue, pull request, or
discussion for a suspected vulnerability — that discloses it to everyone before
there is a fix.

If you prefer to report through GitHub, use
[private vulnerability reporting](https://github.com/Hanalyx/OpenWatch/security/advisories/new)
on this repository. It stays private to the maintainers until an advisory is
published.

Include what you have:

- The version you tested (`openwatch --version`) and how it was installed (RPM,
  DEB, or built from source).
- What an attacker can do, and the privilege level they need to start.
- The exact request, command, or steps to reproduce it. A reproduction we can
  run ourselves is worth more than a description of one.
- Any logs or output that show the effect, with credentials redacted.

Never send live credentials, private keys, license keys, or customer data in a
report. If a finding depends on such material, say so and we will arrange a
channel for it.

## What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement that we received the report | 3 business days |
| Initial assessment and a severity call | 10 business days |
| Fix released, or a written plan with dates if it will take longer | 90 days |

We will tell you which release carries the fix, and we will credit you in the
advisory and the CHANGELOG unless you ask us not to. We ask that you hold public
disclosure until a fix ships or the 90 days elapse, whichever comes first.

## Supported versions

OpenWatch is pre-1.0. Security fixes land on the most recent minor release line
only; there are no long-term support branches yet.

| Version | Supported |
|---------|-----------|
| 0.6.x   | Yes |
| < 0.6.0 | No — upgrade to the current release |

Upgrade instructions are in [docs/runbooks/](docs/runbooks/). Package upgrades
migrate the database automatically and take a backup first.

## Scope

In scope: the OpenWatch server binary and its API, the embedded web UI, the RBAC
and licensing enforcement paths, credential and SSH key handling, the scan
pipeline, and the RPM and DEB packaging and their provisioning scripts.

Out of scope: findings that require an already-compromised host or an existing
administrator account to exploit; missing hardening that has no attacker-reachable
consequence; automated scanner output submitted without a reproduction; denial of
service by resource exhaustion against your own deployment; and vulnerabilities in
the [Kensa](https://github.com/Hanalyx/kensa) scanning engine, which has its own
security policy — report those to the Kensa project.

Security-relevant design decisions and past reviews are documented under
[docs/](docs/README.md).
