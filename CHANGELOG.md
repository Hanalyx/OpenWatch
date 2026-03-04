# Changelog

All notable changes to OpenWatch are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
