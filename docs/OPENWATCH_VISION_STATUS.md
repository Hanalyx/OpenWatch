# OpenWatch vs. Vision Milestones — Status Check

**Date:** 2026-04-13 (updated)
**Source:** Assessment against [OPENWATCH_VISION.md](OPENWATCH_VISION.md) Q1–Q3 milestones

---

## Platform Decision: Linux Containers (FreeBSD evaluated, dropped 2026-04-14)

OpenWatch ships on Linux containers with native RPM and DEB packages for
air-gapped deployment.

- Container base: Red Hat UBI 9 (backend, worker), Alpine (db, frontend)
- FIPS: OpenSSL 3.x FIPS provider module (portable, not tied to Red Hat)
- Native packages: RPM (CentOS Stream 9) and DEB (Ubuntu 24.04)

### Why FreeBSD was evaluated and dropped

A FreeBSD 15.0 minimal container target was scoped in early 2026-04 as part of
the Workstream E dependency-minimization story. The Dockerfiles, compose file,
and pkg packaging skeleton were drafted and merged. Validation revealed there
is no practical path forward:

- Standard Linux Docker hosts (including all developer machines and GitHub
  Actions Linux runners) cannot execute FreeBSD OCI containers — that requires
  OCI v1.3 with a FreeBSD-aware runtime, which only exists on FreeBSD hosts
- GitHub Actions does not provide FreeBSD runners; self-hosted FreeBSD runners
  would need to be procured and maintained
- The native FreeBSD pkg deliverable can serve air-gapped FreeBSD operators
  without requiring containerized FreeBSD at all, but H3 alone did not justify
  the maintenance cost of the container fork

All FreeBSD artifacts (Dockerfile.*.freebsd, docker-compose.freebsd.yml,
packaging/freebsd/) were removed on 2026-04-14.

---
