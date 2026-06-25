# Linux Distribution Support Matrix

> **Scope.** OpenWatch targets Linux, but **not every Linux distribution is
> supported to the same degree** — and compliance *scanning* in particular is
> currently **RHEL-family only**, because that is what the bundled Kensa rule
> corpus covers. This page states, with evidence, which distributions work for
> (1) running the OpenWatch server and (2) being added as a managed/scanned
> host.

**Last Updated:** 2026-06-25 · **Applies to:** OpenWatch 0.2.0-rc series (Go single-binary)

**Last verified:** 2026-06-25 against Kensa rule corpus **v0.6.0** (538 rules).

---

## TL;DR

- **Compliance scanning works on RHEL 8 / 9 / 10 and its binary-compatible
  rebuilds** (Rocky, AlmaLinux, CentOS Stream, Oracle Linux). **Every bundled
  rule declares `platforms: family: rhel`** — there are *no* Ubuntu, Debian,
  Fedora, or SUSE rules in the corpus.
- **Adding a non-RHEL host (e.g. Fedora, Ubuntu) is not blocked**, but the scan
  will **skip 100% of rules** because none apply to that platform. This is
  intentional: running RHEL hardening checks against a different distro would
  report *wrong* compliance, so Kensa skips rather than misreport.
- **Host discovery and Server Intelligence are OS-agnostic** (plain SSH +
  portable probes), so they nominally work on any SSH-reachable Linux —
  but they produce no compliance posture without applicable scan rules.

---

## 1. OpenWatch server (where the application runs)

OpenWatch ships as native packages and containers built for:

| Platform | Form | Notes |
|----------|------|-------|
| **RHEL 9 / CentOS Stream 9** | native **RPM** | Built/tested on CentOS Stream 9 (`packaging/rpm/`). RHEL 9, Rocky 9, AlmaLinux 9 are binary-compatible. |
| **Ubuntu 24.04 LTS** | native **DEB** | Built/tested on Ubuntu 24.04 (`packaging/deb/`). |
| **Container** | OCI images | Backend/worker on UBI 9, db/frontend on Alpine. FIPS via the OpenSSL 3.x FIPS provider. |

Other distributions may run the server from source (Go 1.26 + PostgreSQL 16),
but only the above are packaged, tested, and released.

> The server OS is **independent** of the managed-host OS — you can run the
> OpenWatch server on Ubuntu and scan RHEL hosts, or vice-versa.

---

## 2. Managed / scanned hosts

A host moves through three phases after you add it. Each has different OS
sensitivity:

| Phase | What it does | OS sensitivity |
|-------|--------------|----------------|
| **Discovery** | SSH in, read `/etc/os-release`, fingerprint OS/CPU/mem/disk | **OS-agnostic** — works on any SSH-reachable Linux |
| **Server Intelligence** | Collect packages/services/users/network/firewall | **OS-agnostic** — portable probes; `rpm -qa` *or* `dpkg -l`, `firewall-cmd`/`ufw`/`nft`/`iptables` |
| **Compliance scan (Kensa)** | Evaluate hardening rules, produce posture | **RHEL-family only** — the bundled corpus is 100% `family: rhel` |

### Support matrix

| Distribution | Discovery | Intelligence | Compliance scan | Overall |
|--------------|:---------:|:------------:|:---------------:|---------|
| **RHEL 8 / 9 / 10** | ✅ | ✅ | ✅ full | **Supported** |
| **Rocky Linux 8 / 9** | ✅ | ✅ | ✅ (matches `family: rhel` via `ID_LIKE`) | **Supported** |
| **AlmaLinux 8 / 9** | ✅ | ✅ | ✅ (matches `family: rhel` via `ID_LIKE`) | **Supported** |
| **CentOS Stream 9** | ✅ | ✅ | ✅ (matches `family: rhel` via `ID_LIKE`) | **Supported** |
| **Oracle Linux 8 / 9** | ✅ | ✅ | ✅ (matches `family: rhel` via `ID_LIKE`) | **Supported** |
| **Fedora** | ✅ | ✅ | ❌ **all rules skip** | **Not supported for scanning** |
| **Ubuntu 22.04 / 24.04** | ✅ | ✅ | ❌ **all rules skip** | **Inventory only** |
| **Debian 12** | ✅ | ✅ | ❌ **all rules skip** | **Inventory only** |
| **SUSE / openSUSE / SLES** | ✅ | ✅ | ❌ **all rules skip** | **Inventory only** |
| **Alpine / Arch / Gentoo / other** | ✅ (best-effort) | ⚠️ partial | ❌ **all rules skip** | **Unsupported** |

Legend: ✅ works · ⚠️ partial/unverified · ❌ no coverage.

> **"Inventory only"** means discovery + Server Intelligence populate the host
> (OS, packages, services, etc.) but there is **no compliance posture** — every
> scan reports 0 applicable rules. These distros are *recognized*, just not
> *scannable* with today's corpus.

---

## 3. Why a Fedora (or Ubuntu) host scans nothing

This is the behaviour you will see and it is **working as designed**, not a
crash:

1. **Discovery succeeds.** OpenWatch reads `/etc/os-release` and stores the
   `os_family`. The family is the lower-cased `ID` field
   (`internal/intelligence/discovery/helpers.go:31` `deriveOSFamily`):
   - Fedora → `os_family = "fedora"`
   - Ubuntu → `os_family = "ubuntu"`
   - The `ID_LIKE`→`rhel` rollup only runs when `ID` is **empty**, so a host
     that advertises its own `ID` keeps it. (RHEL clones still match because
     Kensa reads their `ID_LIKE`, which contains `rhel`.)
2. **Server Intelligence succeeds.** The collector branches on no OS family; it
   runs `rpm -qa … || dpkg -l` and portable probes, with partial-success
   semantics (a failed command leaves a field empty, it does not fail the
   cycle).
3. **The compliance scan skips everything.** Kensa SSHes to the host, reads
   `/etc/os-release`, and filters its corpus to rules whose `platforms` match
   the detected distro. **Every rule in v0.6.0 declares `platforms: family:
   rhel`** (version-pinned to `rhel8`/`rhel9`/`rhel10`). A Fedora or Ubuntu
   host matches none, so **all 538 rules are skipped**.

Skipping is the correct outcome: applying RHEL 9 STIG/CIS checks to Fedora 40 or
Ubuntu 24.04 would evaluate the wrong files, services, and defaults and report
**false** compliance.

> **Did Server Intelligence actually fail on your host?** The collector is
> OS-portable, so a *distro* mismatch does not fail it. A genuine intelligence
> failure usually points at the **SSH/sudo/connectivity** for that specific host
> (e.g. the credential can't `sudo`, or the host is unreachable) rather than the
> distribution. Check the host's connectivity tile and the audit log for the
> actual error before assuming it is a Fedora limitation.

---

## 4. How OS family is determined

`deriveOSFamily(osID, osIDLike)` —
`internal/intelligence/discovery/helpers.go:31`:

| Precedence | Source | Result |
|-----------|--------|--------|
| 1 | `/etc/os-release` `ID` (lower-cased) | returned verbatim when non-empty (`rhel`, `ubuntu`, `rocky`, `fedora`, …) |
| 2 | first recognized token in `ID_LIKE` (only if `ID` empty) | rolled up to `rhel` / `debian` / `suse` / `alpine` / `arch` / `gentoo` |
| 3 | neither recognized | `"other"` |

The stored `os_family` drives the frontend OS label and the framework-lens
filter (`internal/server/host_compliance_lens_handler.go`, `osFamilyTokens`).
Note `fedora` is **not** in `osFamilyTokens`, so a Fedora host is also offered no
version-pinned framework lenses.

---

## 5. Adding support for another distribution

Compliance coverage is defined by the **Kensa rule corpus**, not by OpenWatch
application code. To make (say) Ubuntu or Fedora scannable, the
[Kensa](https://github.com/Hanalyx/kensa) project must ship rules that declare
those platforms in their `platforms:` block (e.g. `family: debian` /
`family: fedora`) with the appropriate framework mappings (CIS Ubuntu, etc.).

> **Status:** the **Kensa team is actively expanding distribution coverage.**
> Because applicability lives entirely in the rule corpus, broader distro
> support arrives by **bundling a newer `kensa-rules` package — with no
> OpenWatch code change.** Discovery and Server Intelligence already work on
> those hosts today; only the rules are missing. This matrix should be
> re-verified (the "Last verified" corpus version at the top) whenever the
> bundled Kensa version is bumped.

Until that corpus lands, treat non-RHEL hosts as **inventory-only**: useful for
visibility (packages, services, drift on the intelligence side) but without a
compliance score.

---

## Evidence

- OS-family derivation: `internal/intelligence/discovery/helpers.go:31`
- OS-release parsing: `internal/intelligence/probe/probe.go` (`ParseOSRelease`)
- Collector (OS-agnostic, `rpm || dpkg`): `internal/intelligence/collector/collector.go`
- Kensa invocation / rule load: `internal/kensa/scanfunc.go`, `internal/kensa/catalog.go`
- Framework-lens OS filter (`osFamilyTokens`): `internal/server/host_compliance_lens_handler.go`
- Rule corpus applicability (verified): Kensa v0.6.0 — **538/538 rules `platforms: family: rhel`**, pinned `rhel8`/`rhel9`/`rhel10`
- Framework mappings: `CLAUDE.md` (CIS RHEL 9 v2.0.0, STIG RHEL 9 V2R7)
