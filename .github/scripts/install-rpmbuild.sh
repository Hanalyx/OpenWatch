#!/usr/bin/env bash
# Install rpmbuild (the `rpm` package) on a GitHub-hosted ubuntu runner,
# resiliently.
#
# Why this exists: the hosted ubuntu image preconfigures third-party apt repos
# (packages.microsoft.com, azure-cli, dl.google.com) that intermittently return
# 403 / "no longer signed". `apt-get update` fails as a whole if ANY configured
# repo errors, so an unrelated broken repo kills the step even though `rpm`
# ships from the standard Ubuntu archive. This has flaked the package-smoke and
# release builds. Strip those unneeded third-party sources first, then update
# and install with a short retry for genuine transient mirror blips.
set -euo pipefail

# 1. Drop third-party apt sources we never need for `rpm`. Matched by content
#    (not filename) so it survives the runner renaming the files. Guard each
#    grep so an unreadable/odd file never aborts the loop.
while IFS= read -r -d '' f; do
    if grep -qE 'packages\.microsoft\.com|azure-cli|dl\.google\.com' "$f" 2>/dev/null; then
        sudo rm -f "$f"
        echo "install-rpmbuild: removed unneeded third-party apt source: $f"
    fi
done < <(find /etc/apt/sources.list.d -type f \( -name '*.list' -o -name '*.sources' \) -print0 2>/dev/null)

# 2. Update + install with a few retries (a real transient archive hiccup).
for attempt in 1 2 3; do
    if sudo apt-get update && sudo apt-get install -y --no-install-recommends rpm; then
        echo "install-rpmbuild: rpm installed"
        exit 0
    fi
    echo "install-rpmbuild: apt attempt ${attempt} failed; retrying in $((attempt * 5))s" >&2
    sleep "$((attempt * 5))"
done

echo "install-rpmbuild: could not install rpm after 3 attempts" >&2
exit 1
