# Linux distribution support matrix

> **Scope.** OpenWatch targets Linux, but **not every Linux distribution is
> supported to the same degree**. Compliance *scanning* is supported on the
> **RHEL family and on Ubuntu**, because those are the platforms the bundled
> Kensa rule corpus declares. This page states, with
> evidence, which distributions work for (1) running the OpenWatch server and
> (2) being added as a managed and scanned host. **These are separate
> questions with separate answers**: the server list comes from the release
> gate, the scan list from the bundled rule corpus.

**Counts on this page are release-dependent and were derived, not copied.**
They describe one corpus version and change whenever the bundled Kensa
dependency moves, so they are dated and reproducible rather than stated as
permanent facts.

**Derived 2026-09-11** from the corpus this repository ships, by reading each
rule's `platforms:` declaration. Reproduce it yourself:

```sh
KDIR=$(go list -m -f '{{.Dir}}' github.com/Hanalyx/kensa)
find "$KDIR/rules" -name '*.y*ml' | wc -l          # total rules
```

The version comes from `go.mod`, which is the authority for the compiled Kensa
dependency, and the corpus comes from that same module: `packaging/common/
stage-kensa-rules.sh` copies `<module>/rules/**` into the `kensa-rules`
package. **This is the one page where naming the Kensa version is necessary**,
because a per-OS rule count means nothing without saying which corpus produced
it. Everywhere else in the guides, the corpus is described rather than
numbered.

---

## TL;DR

- **Compliance scanning works on RHEL 8 / 9 / 10** and its binary-compatible
  rebuilds (Rocky, AlmaLinux, CentOS Stream, Oracle Linux), **and on Ubuntu
  22.04 / 24.04 LTS.** A single host is measured against the subset of the
  corpus that applies to its operating system, never against all of it.
- **Each rule declares the platforms it applies to**, so a host is only
  evaluated against rules that match its detected OS. Ubuntu hosts are scanned
  against the Ubuntu rule set; RHEL hosts against the RHEL rule set.
- **Fedora, Debian, and SUSE are inventory only as scan targets**: the corpus
  carries no rules for them, so a scan reports 0 applicable rules. This is
  intentional: running rules written for another distribution would report
  *wrong* compliance, so Kensa skips rather than misreport. This is a statement
  about scanning a host, not about where the server runs. Debian 12 is a
  release-tested server platform and an inventory-only scan target at the same
  time.
- **The server runs on four release-tested platforms**: RHEL 9, AlmaLinux 10,
  Ubuntu 24.04 LTS and Debian 12. See section 1.
- **Host discovery and Server Intelligence are OS-agnostic** (plain SSH +
  portable probes), so they work on any SSH-reachable Linux, including the
  inventory-only distros.

---

## 1. OpenWatch server (where the application runs)

OpenWatch ships as native packages. Four platforms are **release-tested**:
each is a blocking platform in `release/gates.toml`, each has a CI job that
runs `openwatch setup` on release tags, on pull requests that touch the
packaging or installer paths, and on manual dispatch, and each returns
`SupportTested` from
`supportOf` in `internal/setup/platform.go`.

| Release-tested platform | Form |
|----------|------|
| **RHEL 9** | native **RPM** |
| **AlmaLinux 10** | native **RPM** |
| **Ubuntu 24.04 LTS** | native **DEB** |
| **Debian 12** | native **DEB** |

**"Release-tested" describes what CI proves, not a commercial support or
service-level promise.** It means a job installs the package on that platform
on those triggers and asserts the result, and that a release cannot be promoted
while that job is failing.

**AlmaLinux 10 is release-tested; RHEL 10 is not.** The matrix has an
AlmaLinux 10 image and no RHEL 10 image, so the claim stops where the evidence
stops rather than extending to the whole EL10 line.

### Wider package-install coverage

A second CI job installs the built package and checks its files on a longer
list of images: `rockylinux:9`, `almalinux:9`, `oraclelinux:9`, `fedora:41`,
`almalinux:10`, `ubuntu:24.04` and `debian:12`. That job proves the package
installs. It does **not** run `openwatch setup`, stand up PostgreSQL, or start
the service, so it is a weaker claim than release-tested.

RHEL 9, Rocky 9, AlmaLinux 9 and Oracle Linux 9 are binary-compatible, so the
RPM behaves the same on them. `openwatch setup` still classifies the rebuilds
as **untested** and asks for `--allow-untested`, because only `ID=rhel` at
major 9 is release-tested. The CI job that installs on `rockylinux:9` passes
that flag for exactly this reason: no container can be a licensed RHEL host.

**Fedora and SUSE are not supported server platforms.** `openwatch setup`
classifies Fedora as *unsupported*: it is recognized as RHEL-family, but its
major version falls outside the 8 to 10 range the setup code models. SUSE is
not recognized as any family, so it is unsupported too. The Fedora entry in
the package-install list above proves only that the RPM unpacks there.

Any distribution may run the server from source (Go 1.26 + PostgreSQL 14 or
newer). That is unsupported in the sense above: nothing in CI proves it.

> The server OS is **independent** of the managed-host OS. You can run the
> OpenWatch server on Ubuntu and scan RHEL hosts, or vice-versa.

---

## 2. Managed and scanned hosts

A host moves through three phases after you add it. Each has different OS
sensitivity:

| Phase | What it does | OS sensitivity |
|-------|--------------|----------------|
| **Discovery** | SSH in, read `/etc/os-release`, fingerprint OS/CPU/mem/disk | **OS-agnostic**: works on any SSH-reachable Linux |
| **Server Intelligence** | Collect packages/services/users/network/firewall | **OS-agnostic**: portable probes; `rpm -qa` *or* `dpkg -l`, `firewall-cmd`/`ufw`/`nft`/`iptables` |
| **Compliance scan (Kensa)** | Evaluate hardening rules, produce posture | **RHEL family and Ubuntu**: each rule is filtered to the platforms it declares |

### Per-OS rule applicability

Read from each rule's `platforms:` block in the bundled corpus. **Derived
2026-09-11 from Kensa v0.9.0**, the version `go.mod` pins:

| OS family | Rules applicable |
|-----------|-------------------|
| RHEL family (RHEL, Rocky, AlmaLinux, CentOS Stream, Oracle Linux) | 677 |
| Ubuntu (22.04, 24.04) | 272 |

A rule can apply to several platforms, so these counts overlap: 497 rules
declare RHEL only, 92 declare Ubuntu only, and 180 declare both, giving 769
rules in total.

**Expect these to move.** They are a property of one corpus version, not of
OpenWatch. Re-derive them with the command above whenever the Kensa
dependency is bumped.

### Support matrix for managed hosts

**This table is about hosts you add and scan, not about where the server
runs.** The two are independent, and a distribution can sit in different rows
of each. Debian 12 is the clearest case: it is a **release-tested server
platform** (section 1) and an **inventory-only scan target**, because the
bundled rule corpus carries no Debian rules. Neither fact softens the other.

| Distribution | Discovery | Intelligence | Compliance scan | Overall as a scanned host |
|--------------|-----------|--------------|-----------------|---------|
| **RHEL 8 / 9 / 10** | Supported | Supported | Supported, full | **Supported** |
| **Rocky Linux 8 / 9** | Supported | Supported | Supported (matches RHEL family via `ID_LIKE`) | **Supported** |
| **AlmaLinux 8 / 9** | Supported | Supported | Supported (matches RHEL family via `ID_LIKE`) | **Supported** |
| **CentOS Stream 9** | Supported | Supported | Supported (matches RHEL family via `ID_LIKE`) | **Supported** |
| **Oracle Linux 8 / 9** | Supported | Supported | Supported (matches RHEL family via `ID_LIKE`) | **Supported** |
| **Ubuntu 22.04 / 24.04 LTS** | Supported | Supported | Supported | **Supported** |
| **Fedora** | Supported | Supported | Not supported, **all rules skip** | **Inventory only** |
| **Debian 12** | Supported | Supported | Not supported, **all rules skip** | **Inventory only** as a scan target. Release-tested as a *server* platform. |
| **SUSE / openSUSE / SLES** | Supported | Supported | Not supported, **all rules skip** | **Inventory only** |
| **Alpine / Arch / Gentoo / other** | Supported (best-effort) | Partial | Not supported, **all rules skip** | **Unsupported** |

Legend: **Supported** means the phase works; **Partial** means partial or
unverified support; **Not supported** means no coverage for that phase.

> **"Inventory only"** means discovery and Server Intelligence populate the
> host (OS, packages, services, and so on) but there is **no compliance
> posture**: every scan reports 0 applicable rules. These distributions are
> *recognized*, but not *scannable* with today's corpus. This says nothing
> about whether the OpenWatch server runs on them; see section 1 for that.

---

## 3. Why a Fedora or Debian host scans nothing

This is the behavior you see and it is **working as designed**, not a
crash:

1. **Discovery succeeds.** OpenWatch reads `/etc/os-release` and stores the
   `os_family`. The family is the lower-cased `ID` field:
   - Fedora → `os_family = "fedora"`
   - Debian → `os_family = "debian"`
   - The `ID_LIKE`-to-`rhel` rollup only runs when `ID` is **empty**, so a host
     that advertises its own `ID` keeps it. (RHEL clones still match because
     Kensa reads their `ID_LIKE`, which contains `rhel`.)
2. **Server Intelligence succeeds.** The collector branches on no OS family; it
   runs `rpm -qa … || dpkg -l` and portable probes, with partial-success
   semantics (a failed command leaves a field empty, it does not fail the
   cycle).
3. **The compliance scan skips everything.** Kensa SSHes to the host, reads
   `/etc/os-release`, and filters its corpus to rules whose `platforms` match
   the detected distro. The Kensa rule corpus carries rules for the RHEL family
   and Ubuntu only, so a Fedora, Debian, or SUSE host matches none and **all
   rules are skipped**.

Skipping is the correct outcome: applying rules written for one distro to
another would evaluate the wrong files, services, and defaults and report
**false** compliance.

> **Did Server Intelligence actually fail on your host?** The collector is
> OS-portable, so a *distro* mismatch does not fail it. A genuine intelligence
> failure usually points at the **SSH/sudo/connectivity** for that specific host
> (for example the credential can't `sudo`, or the host is unreachable) rather than the
> distribution. Check the host's connectivity tile and the audit log for the
> actual error before assuming it is a distribution limitation.

---

## 4. How OS family is determined

OpenWatch derives the OS family from `/etc/os-release` as follows:

| Precedence | Source | Result |
|-----------|--------|--------|
| 1 | `/etc/os-release` `ID` (lower-cased) | returned verbatim when non-empty (`rhel`, `ubuntu`, `rocky`, `fedora`, …) |
| 2 | first recognized token in `ID_LIKE` (only if `ID` empty) | rolled up to `rhel` / `debian` / `suse` / `alpine` / `arch` / `gentoo` |
| 3 | neither recognized | `"other"` |

The stored `os_family` drives the frontend OS label and the framework-lens
filter. RHEL and Ubuntu hosts are offered the framework lenses for their
detected OS; an inventory-only distro (such as Fedora) is offered no
version-pinned framework lenses.

---

## 5. Adding support for another distribution

Compliance coverage is defined by the **Kensa rule corpus**, not by OpenWatch
application code. To make (say) Debian or Fedora scannable, the
[Kensa project](https://github.com/Hanalyx/kensa) must ship rules that declare
those platforms in their `platforms:` block with the appropriate framework
mappings.

> **Status:** the **Kensa team is actively expanding distribution coverage.**
> Ubuntu 22.04 / 24.04 support arrived in Kensa v0.7.0. Because applicability
> lives entirely in the rule corpus, broader distro support arrives by
> **bundling a newer `kensa-rules` package, with no OpenWatch code change.**
> Discovery and Server Intelligence already work on those hosts today; only the
> rules are missing. This matrix should be re-verified (the "Last verified"
> corpus version at the top) whenever the bundled Kensa version is bumped.

Until that corpus lands, treat unsupported distros as **inventory-only**: useful
for visibility (packages, services, drift on the intelligence side) but without
a compliance score.

---

## Evidence

- OS-family derivation reads `/etc/os-release` (`ID`, then `ID_LIKE`).
- Server Intelligence is OS-agnostic: it runs `rpm -qa` or `dpkg -l` with
  partial-success semantics.
- Kensa filters its corpus by the host's detected platform at scan time.
- Rule corpus applicability, read from the corpus platform declarations and
  derived 2026-09-11 from Kensa v0.9.0 as pinned in `go.mod`: **769 rules**
  spanning RHEL 8/9/10 and Ubuntu 22.04/24.04, of which 677 apply to the RHEL
  family and 272 to Ubuntu. Rules can apply to more than one platform, so
  these overlap.
- Framework mappings: CIS RHEL 9 v2.0.0, STIG RHEL 9 V2R7, plus CIS/STIG Ubuntu.
