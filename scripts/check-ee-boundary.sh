#!/usr/bin/env bash
# check-ee-boundary: enforce the one-way licensing dependency.
#
# The permissively licensed core (internal/, cmd/) must NEVER import the
# separately licensed ee/ module tree. EE capabilities are reached only through
# internal/eereg; the ee module depends on the core, never the reverse. This
# guard fails the build if any core package transitively imports <module>/ee.
#
# It inspects the CE (default, no-tags) build graph: the `-tags ee` wiring file
# is excluded there, so a clean tree reports nothing.
set -euo pipefail

MODULE="github.com/Hanalyx/openwatch"

# -deps gives the full transitive import set of the named packages.
deps="$(go list -deps ./cmd/... ./internal/...)"

if printf '%s\n' "$deps" | grep -qE "^${MODULE}/ee(/|\$)"; then
	echo "ERROR: a core package (internal/ or cmd/) imports ${MODULE}/ee" >&2
	echo "       The core must reach EE capabilities only via internal/eereg." >&2
	echo "       Offending dependency path(s):" >&2
	printf '%s\n' "$deps" | grep -E "^${MODULE}/ee(/|\$)" >&2
	exit 1
fi

echo "ee-boundary OK: core (internal/, cmd/) does not import ${MODULE}/ee"
