#!/usr/bin/env bash
# go-test-report.sh: print the failed tests and their failure output from a
# `go test -json` stream, for the Go CI log. Used by both test jobs in
# .github/workflows/go-ci.yml so a failure names the test the same way in
# either one.
#
# Usage: go-test-report.sh <label> <go-test-json-file>
set -euo pipefail
label="${1:?usage: go-test-report.sh <label> <json>}"
json="${2:?usage: go-test-report.sh <label> <json>}"
echo "::group::Failed tests ($label)"
jq -r 'select(.Action=="fail" and .Test != null) | "FAIL  \(.Package)  \(.Test)"' "$json" | sort -u
echo "::endgroup::"
echo "::group::Failure output ($label, last 80 lines)"
jq -r 'select(.Action=="output" and (.Output | ascii_downcase | test("--- fail|panic:|fatal error|error:"))) | "\(.Package): \(.Output)"' "$json" | tail -n 80
echo "::endgroup::"
