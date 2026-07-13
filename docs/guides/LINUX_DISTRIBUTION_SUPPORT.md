# Linux distribution support matrix

> **Scope.** OpenWatch targets Linux, but **not every Linux distribution is
> supported to the same degree**. As of Kensa v0.7.6, compliance *scanning* is
> supported on the **RHEL family and on Ubuntu**, because those are the
> platforms the bundled Kensa rule corpus covers. This page states, with
> evidence, which distributions work for (1) running the OpenWatch server and
> (2) being added as a managed/scanned host.

**Last updated:** 2026-06-29 · **Applies to:** OpenWatch v0.3.0 (Go single-binary)

**Last verified:** 2026-07-13 against Kensa rule corpus **v0.7.6** (748 rules).
Per-OS counts below are read from each rule's `platforms:` declarations in the
v0.7.6 corpus, not from a live scan.

---

## TL;DR

- **Compliance scanning works on RHEL 8 / 9 / 10** and its binary-compatible
  rebuilds (Rocky, AlmaLinux, CentOS Stream, Oracle Linux), **and on Ubuntu
  22.04 / 24.04 LTS.** Kensa v0.7.6 ships 748 rules across these platforms.
- **Each rule declares the platforms it applies to**, so a host is only
  evaluated against rules that match its detected OS. Ubuntu hosts are scanned
  against the Ubuntu rule set; RHEL hosts against the RHEL rule set.
- **Fedora, Debian, and SUSE remain inventory only**—the corpus carries no rules
  for them, so a scan reports 0 applicable rules. This is intentional: running
  rules written for another distro would report *wrong* compliance, so Kensa
  skips rather than misreport.
- **Host discovery and Server Intelligence are OS-agnostic** (plain SSH +
  portable probes), so they work on any SSH-reachable Linux, including the
  inventory-only distros.

---

## 1. OpenWatch server (where the application runs)

OpenWatch ships as native packages built for:

| Platform | Form | Notes |
|----------|------|-------|
| **RHEL 9** | native **RPM** | Built on `ubuntu-latest` CI runners cross-packaging the RPM; smoke-tested in `rockylinux:9` and `almalinux:9` containers. RHEL 9, Rocky 9, AlmaLinux 9 are binary-compatible. |
| **Ubuntu 24.04 LTS** | native **DEB** | Built/tested on Ubuntu 24.04. |

Other distributions may run the server from source (Go 1.26 + PostgreSQL 14 or
newer), but only the above are packaged, tested, and released.

> The server OS is **independent** of the managed-host OS. You can run the
> OpenWatch server on Ubuntu and scan RHEL hosts, or vice-versa.

---

## 2. Managed and scanned hosts

A host moves through three phases after you add it. Each has different OS
sensitivity:

| Phase | What it does | OS sensitivity |
|-------|--------------|----------------|
| **Discovery** | SSH in, read `/etc/os-release`, fingerprint OS/CPU/mem/disk | **OS-agnostic**—works on any SSH-reachable Linux |
| **Server Intelligence** | Collect packages/services/users/network/firewall | **OS-agnostic**—portable probes; `rpm -qa` *or* `dpkg -l`, `firewall-cmd`/`ufw`/`nft`/`iptables` |
| **Compliance scan (Kensa)** | Evaluate hardening rules, produce posture | **RHEL family and Ubuntu**—each rule is filtered to the platforms it declares |

### Per-OS rule applicability

Rule applicability is read from the currently bundled Kensa v0.7.6 corpus
(each rule's `platforms:` block). These are the counts of rules that apply per
OS family:

| OS family | Rules applicable |
|-----------|-------------------|
| RHEL family (RHEL, Rocky, AlmaLinux, CentOS Stream, Oracle Linux) | 668 |
| Ubuntu (22.04, 24.04) | 117 |

A rule can apply to several platforms, so these counts overlap; the Kensa
v0.7.6 corpus total is 748 distinct rules.

### Support matrix

| Distribution | Discovery | Intelligence | Compliance scan | Overall |
|--------------|-----------|--------------|-----------------|---------|
| **RHEL 8 / 9 / 10** | Supported | Supported | Supported, full | **Supported** |
| **Rocky Linux 8 / 9** | Supported | Supported | Supported (matches RHEL family via `ID_LIKE`) | **Supported** |
| **AlmaLinux 8 / 9** | Supported | Supported | Supported (matches RHEL family via `ID_LIKE`) | **Supported** |
| **CentOS Stream 9** | Supported | Supported | Supported (matches RHEL family via `ID_LIKE`) | **Supported** |
| **Oracle Linux 8 / 9** | Supported | Supported | Supported (matches RHEL family via `ID_LIKE`) | **Supported** |
| **Ubuntu 22.04 / 24.04 LTS** | Supported | Supported | Supported (117 applicable rules) | **Supported** |
| **Fedora** | Supported | Supported | Not supported, **all rules skip** | **Inventory only** |
| **Debian 12** | Supported | Supported | Not supported, **all rules skip** | **Inventory only** |
| **SUSE / openSUSE / SLES** | Supported | Supported | Not supported, **all rules skip** | **Inventory only** |
| **Alpine / Arch / Gentoo / other** | Supported (best-effort) | Partial | Not supported, **all rules skip** | **Unsupported** |

Legend: **Supported** means the phase works; **Partial** means partial or
unverified support; **Not supported** means no coverage for that phase.

> **"Inventory only"** means discovery + Server Intelligence populate the host
> (OS, packages, services, and so on) but there is **no compliance posture**—every
> scan reports 0 applicable rules. These distros are *recognized*, but not
> *scannable* with today's corpus.

---

## 3. Why a Fedora or Debian host scans nothing

This is the behaviour you see and it is **working as designed**, not a
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
- Rule corpus applicability (read from the corpus platform declarations): the
  currently bundled corpus is Kensa v0.7.6, **748 rules** spanning RHEL
  8/9/10 and Ubuntu 22.04/24.04—668 applicable to the RHEL family, 117 to
  Ubuntu (rules can apply to more than one platform, so these overlap).
- Framework mappings: CIS RHEL 9 v2.0.0, STIG RHEL 9 V2R7, plus CIS/STIG Ubuntu.
