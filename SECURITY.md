# Security Policy

## Reporting a vulnerability

Email **security@hanalyx.com**. Do not open a public issue, pull request, or
discussion for a suspected vulnerability. That discloses it to everyone before
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
| Acknowledgment that we received the report | 3 business days |
| Initial assessment and a severity call | 10 business days |
| Fix released, or a written plan with dates if it will take longer | 90 days |

We will tell you which release carries the fix, and we will credit you in the
advisory and the CHANGELOG unless you ask us not to. We ask that you hold public
disclosure until a fix ships or the 90 days elapse, whichever comes first.

## Supported versions

OpenWatch is pre-1.0 and still stabilizing. Only the latest published stable
release is supported.

- **Published** means its GitHub release is public and not marked as a
  pre-release. Merging a change, creating a tag or building a draft release does
  not make a version supported.
- **Until 0.8.3 is published,** the latest published stable release is 0.7.1,
  and 0.7.1 is supported.
- **Once 0.8.3 is published,** it is the only supported release. 0.7.1 and
  every earlier release are no longer supported. Users on an earlier version
  should upgrade promptly.
- **Security fixes target the latest published stable release.** Backports to
  older releases are not promised.

| Version | Supported |
|---------|-----------|
| The latest published stable release: 0.7.1 until 0.8.3 is published, then 0.8.3 | Yes |
| Any earlier stable release | No. Upgrade to the latest published stable release |
| 0.8.0, 0.8.1, 0.8.2 | No. Tagged and built as drafts and never published |
| Release candidates, such as 0.8.0-rc.6 | No. Pre-releases for evaluation, not stable releases |

### The tested upgrade path

Upgrade with the [upgrade procedure](docs/runbooks/UPGRADE_PROCEDURE.md). Upgrade
the `openwatch` and `kensa-rules` packages together, in one transaction. The
package upgrade takes a database backup and applies migrations itself.

What has been tested for the 0.8 line:

- **0.7.1 to 0.8, on a real RHEL 9 host.** The 0.8 candidates were upgraded
  from 0.7.1 by following the upgrade procedure, including Step 8.
- **Package upgrades in CI on Rocky Linux 9 and AlmaLinux 10.** CI upgrades the
  published 0.6.0 release, not 0.7.1, to the build under test.
- **Fresh installs in CI on Debian 12 and Ubuntu 24.04.** An upgrade from an
  earlier release on Debian or Ubuntu is not tested.

Precautions when upgrading from 0.7.x to 0.8.x. The release notes in
[CHANGELOG.md](CHANGELOG.md) give the details:

- **The upgrade signs everyone out once.** Migration 0065 revokes every session
  and refresh token. API tokens (`owk_`) keep working.
- **API tokens with no owner stop working.** List and replace them before you
  upgrade.
- **API clients that sign out with cookies must send the CSRF token.**
- **An audit export with an unknown query parameter is refused** with `400`
  instead of exporting everything.
- **Restart after the upgrade and compare the rules.** Follow Step 8 of the
  upgrade procedure. The service the package starts can keep serving rules the
  upgrade removed until it restarts.
- **A rollback across a schema change needs the full rollback.** That procedure
  restores the pre-upgrade database. Reinstalling the old package alone is not
  enough.

### Compatibility in 0.x releases

OpenWatch keeps its existing version numbers. Before 1.0, a release that
changes the second number, such as 0.7 to 0.8, can require significant
migration work, so compatibility is not implied by the number alone:

- **Database migrations** run when the package upgrades. They cannot be undone
  without restoring the backup taken before the upgrade.
- **API changes can break clients.** A route can start refusing requests it used
  to accept.
- **Sign-in and session behavior can change.** This can sign users out.
- **Configuration and packaging requirements can change.** An example is the
  pairing between `openwatch` and `kensa-rules`.

The release notes for each release state its compatibility and upgrade
requirements under "Upgrade notes". Read them for every release between your
version and the one you are installing, including patch releases.

## Scope

In scope: the OpenWatch server binary and its API, the embedded web UI, the RBAC
and licensing enforcement paths, credential and SSH key handling, the scan
pipeline, and the RPM and DEB packaging and their provisioning scripts.

Out of scope: findings that require an already-compromised host or an existing
administrator account to exploit; missing hardening that has no attacker-reachable
consequence; automated scanner output submitted without a reproduction; denial of
service by resource exhaustion against your own deployment; and vulnerabilities in
the [Kensa](https://github.com/Hanalyx/kensa) scanning engine, which has its own
security policy. Report those to the Kensa project.

Security-relevant design decisions and past reviews are documented under
[docs/](docs/README.md).
