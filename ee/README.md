# OpenWatch Enterprise (EE) Modules

> **License:** see [`ee/LICENSE`](LICENSE) — commercial / source-available.
> **Not** Apache 2.0. The Apache license on the OpenWatch core does not extend
> to this directory.

This directory holds optional, separately licensed feature modules. The
permissively licensed core (`internal/`, `cmd/`) never imports `ee/`; it reaches
EE capabilities only through the injection seam in `internal/eereg`. An EE build
(`go build -tags ee`) blank-imports this tree so its `init` registers
implementations; the default community build excludes it entirely and runs as a
complete product on the free-tier defaults.

The boundary (core never imports `ee/`) is enforced two ways:
`scripts/check-ee-boundary.sh` (in `make check`) and `TestCoreDoesNotImportEE`
(spec `system-ee-capability-seam`, AC-04).

EE features are built here per the feature carve. None are present yet; this
tree is established with the open-core relicensing so the boundary and license
are in place before the first feature lands.
