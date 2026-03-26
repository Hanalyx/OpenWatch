# Changelog

All notable changes to OpenWatch are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.0-alpha.1] Eyrie — 2026-03-24

First Alpha release with CI hardening, OpenSCAP removal, and production-grade security controls.

### Added

- Native RPM and DEB quickstart guide in `docs/guides/QUICKSTART.md` and `docs/guides/INSTALLATION.md`
- Bandit security linter enforced in CI (HIGH+ findings block merges)
- MyPy type checking enforced in CI (no longer silently ignored)
- Prettier formatting enforced in CI (no longer non-blocking)
- Backend test coverage threshold raised to 50% (from 31%)

### Changed

- Version bumped from `0.0.0-dev` to `0.1.0-alpha.1`
- Flake8, Black, and isort line length aligned to 100 characters across CI and pyproject.toml
- Frontend build artifact CI path corrected from `dist/` to `build/`
- Remediation types renamed from `ScapCommand`/`ScapConfiguration`/`ScapRemediationData` to generic `RemediationCommand`/`RemediationConfiguration`/`RemediationData`
- Pre-flight validation references Kensa instead of OpenSCAP
- Settings About page describes Kensa-based scanning instead of SCAP/OpenSCAP
- Host card default scan name changed from "SCAP Compliance Scan" to "Compliance Scan"

### Removed

- All OpenSCAP/SCAP/oscap references from frontend source (20+ files updated)
- Dead SCAP-era components: `GroupComplianceScanner.tsx`, `BulkConfigurationDialog.tsx`, `GroupCompatibilityReport.tsx`
- Hardcoded default database credentials from `init_admin.py`

### Security

- `init_admin.py` no longer contains hardcoded database credentials; `OPENWATCH_DATABASE_URL` env var is now required
- Bandit and Safety dependency scanner results now block CI (previously ignored)

---

## [0.0.0-dev] Eyrie — 2026-03-03

Initial pre-release establishing centralized version management and packaging infrastructure.

### Added

- `packaging/version.env` as the single source of truth for `VERSION` and `CODENAME`
- `Codename` build variable in `owadm` (`internal/owadm/cmd/root.go`), injectable via ldflags
- RPM macro-based version injection: `%{ow_version}`, `%{ow_release}`, `%{ow_codename}`
- `--define` flags in `build-rpm.sh` pass version macros to `rpmbuild` at build time
- Debian pre-release versioning convention in `build-deb.sh` (`0.0.0~dev1` format)
- `packaging/tests/test_version_consistency.sh` — 11-check consistency gate across all version-bearing files
- `specs/release/changelog.spec.yaml` — behavioral spec for changelog format and update workflow

### Changed

- `owadm --version` output now includes codename: `0.0.0-dev (Eyrie) (commit: ..., built: ...)`
- `packaging/rpm/openwatch.spec`: hardcoded `Version: 2.0.0` → macro `%{ow_version}`
- `packaging/rpm/openwatch-po.spec`: hardcoded `Version: 2.0.0` → macro `%{ow_version}`
- `packaging/rpm/build-rpm.sh`: hardcoded `version="1.2.1"` → sourced from `version.env`
- `packaging/deb/build-deb.sh`: `git describe` version detection → sourced from `version.env`
- `packaging/deb/DEBIAN/control`: placeholder `Version: 1.0.0` → `0.0.0` (injected at build time)
- `pyproject.toml` version: `1.2.0` → `0.0.0.dev0` (PEP 440 canonical form)
- `frontend/package.json` version: `1.2.0` → `0.0.0-dev`

---
