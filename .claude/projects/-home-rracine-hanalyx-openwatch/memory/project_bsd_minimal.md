---
name: BSD minimal platform decision
description: OpenWatch will target BSD minimal as base for all containers and native deployments, replacing the current mix of Red Hat UBI 9 + Alpine + Debian
type: project
---

OpenWatch targets BSD minimal for all container images and native deployments (decision 2026-04-13).

**Why:** Minimize dependencies and attack surface for air-gapped federal environments. Current setup uses 3 different distros (UBI 9, Debian, Alpine) across 6 containers.

**How to apply:** When creating Dockerfiles, packaging scripts, or system-level code, target BSD minimal — not Alpine, not UBI 9, not Debian. FIPS compliance via OpenSSL 3.x FIPS provider module (portable, not tied to Red Hat's CMVP certificate). Native packages will include FreeBSD pkg format alongside RPM/DEB.
