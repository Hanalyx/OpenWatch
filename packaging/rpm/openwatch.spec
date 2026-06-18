%global goipath github.com/Hanalyx/openwatch
%global debug_package %{nil}

# Disable problematic auto-debug processing on Go binaries.
%define _build_id_links none

# Disable shebang stripping (no shebang in compiled binary, but be safe).
%global __brp_mangle_shebangs %{nil}

# Don't strip the binary. The Go binary is self-contained and prebuilt outside
# the chroot, so RPM's brp-strip adds nothing — and for cross-arch builds
# (e.g. aarch64 RPM on an x86_64 host) the host `strip` cannot process the
# target binary and aborts %install. A no-op keeps cross-builds working.
%global __strip /bin/true

# Allow override via rpmbuild --define "ow_version X.Y.Z".
%{!?ow_version: %global ow_version 0.1.0}
%{!?ow_release: %global ow_release 1}

Name:           openwatch
# Epoch 1 is a permanent, deliberate bump. Releases rc.3 through rc.8 shipped
# with the pre-release suffix stripped, so they all carried the NVR
# openwatch-0.2.0-1 (Epoch 0). The build now encodes pre-releases with a tilde
# (0.2.0~rc.N, which sorts below GA 0.2.0), but 0.2.0~rc.N < 0.2.0 would read as
# a DOWNGRADE from those mis-versioned installs. Epoch 1 sorts strictly above
# Epoch 0, so `dnf upgrade` cleanly moves a bare-0.2.0 install onto the
# correctly-versioned packages. Epoch is sticky: never lower it.
Epoch:          1
Version:        %{ow_version}
Release:        %{ow_release}%{?dist}
Summary:        OpenWatch Compliance Platform (Go binary)

License:        Proprietary
URL:            https://github.com/Hanalyx/openwatch
Source0:        %{name}-%{version}.tar.gz

Requires:       postgresql-server
# Hard dependency on the rule corpus: the kensa engine loads rules from
# /usr/share/kensa/rules at runtime and cannot scan without them. Declaring
# it here makes a corpus-less install fail fast (air-gapped operators install
# both files in one transaction: dnf install ./openwatch-*.rpm ./kensa-rules-*.rpm)
# rather than the service booting and every scan failing. Unversioned so the
# corpus can advance on its own line; tighten to a floor when OTA lands.
Requires:       kensa-rules
# openssl: the %post scriptlet generates the JWT signing key and credential
# DEK at install time (the server refuses to auto-generate them in production).
Requires:       openssl
Requires(pre):  shadow-utils

%description
OpenWatch is the Go rebuild of the compliance scanning platform.
This package ships the single binary, default TOML config, and a
hardened systemd unit. A demo TLS cert is generated at install time
(generate-if-absent, so upgrades never overwrite it). Operators replace
/etc/openwatch/tls/* with their own certificate before production use.

%prep
%setup -q

%build
# Binary is prebuilt by build-rpm.sh — this %build is a no-op so
# rpmbuild doesn't try to invoke the Go toolchain inside the chroot.

%install
install -d -m 0755                  %{buildroot}/usr/bin
install -m 0755 openwatch           %{buildroot}/usr/bin/openwatch

install -d -m 0750                  %{buildroot}/etc/openwatch
# TLS directory. The demo cert + key are NOT shipped in the payload — if they
# were, a package upgrade would silently overwrite an operator's replacement
# certificate (TLS files are not %config). %post generates a demo cert here
# only when absent, mirroring the identity-key model below.
install -d -m 0750                  %{buildroot}/etc/openwatch/tls
# Identity-key directory. The keys themselves are NOT shipped in the payload
# (they must be unique per install); %post generates them into here.
install -d -m 0750                  %{buildroot}/etc/openwatch/keys
install -m 0640 openwatch.toml      %{buildroot}/etc/openwatch/openwatch.toml
install -m 0640 upgrade.conf        %{buildroot}/etc/openwatch/upgrade.conf

install -d -m 0755                  %{buildroot}/usr/lib/openwatch
install -m 0755 provision-identity-keys.sh %{buildroot}/usr/lib/openwatch/provision-identity-keys.sh
install -m 0755 provision-tls-cert.sh %{buildroot}/usr/lib/openwatch/provision-tls-cert.sh
install -m 0755 openwatch-upgrade.sh %{buildroot}/usr/lib/openwatch/openwatch-upgrade.sh
install -m 0755 cleanup-backups.sh   %{buildroot}/usr/lib/openwatch/cleanup-backups.sh

install -d -m 0755                  %{buildroot}/etc/systemd/system
install -m 0644 openwatch.service   %{buildroot}/etc/systemd/system/openwatch.service
install -m 0644 openwatch-backup-cleanup.service %{buildroot}/etc/systemd/system/openwatch-backup-cleanup.service
install -m 0644 openwatch-backup-cleanup.timer   %{buildroot}/etc/systemd/system/openwatch-backup-cleanup.timer

install -d -m 0750                  %{buildroot}/var/lib/openwatch
# Pre-upgrade DB dumps land here (written by the upgrade scriptlet).
install -d -m 0750                  %{buildroot}/var/lib/openwatch/backups
install -d -m 0750                  %{buildroot}/var/log/openwatch

%pre
# AC-11: create system user + group at install time, idempotently.
getent group openwatch >/dev/null || groupadd --system openwatch
getent passwd openwatch >/dev/null || \
    useradd --system --gid openwatch --home-dir /var/lib/openwatch \
            --shell /sbin/nologin --comment "OpenWatch service" openwatch

%post
# AC-07: pick up the new unit file.
systemctl daemon-reload || :

# Provision the identity keys (JWT signing key + credential DEK) the server
# requires in production. Generate-if-absent, so upgrades never clobber the
# live keys. Runs after %pre created the openwatch user/group. Not guarded
# with `|| :`: a real failure here (e.g. a filesystem error) should surface
# as a scriptlet warning, not silently leave an unbootable service.
/usr/lib/openwatch/provision-identity-keys.sh

# Provision a demo TLS cert + key (generate-if-absent). Not shipped in the
# payload so an upgrade never overwrites an operator's replacement cert.
/usr/lib/openwatch/provision-tls-cert.sh

# Enable the daily pre-upgrade-backup cleanup timer (install + upgrade).
systemctl enable --now openwatch-backup-cleanup.timer >/dev/null 2>&1 || :

# On UPGRADE ($1 -ge 2), apply pending DB migrations with an auto-backup
# restore point and a fail-safe service state (stop -> backup+migrate ->
# start, or leave stopped on failure). Skipped on a FRESH install ($1 == 1):
# there is no database yet — the operator runs the documented first-run
# `openwatch migrate` after provisioning Postgres.
if [ "$1" -ge 2 ]; then
    /usr/lib/openwatch/openwatch-upgrade.sh
fi

%preun
# AC-09: stop and disable cleanly so removal doesn't leave a running orphan.
if [ $1 -eq 0 ]; then
    systemctl stop openwatch.service >/dev/null 2>&1 || :
    systemctl disable openwatch.service >/dev/null 2>&1 || :
    systemctl disable --now openwatch-backup-cleanup.timer >/dev/null 2>&1 || :
fi

%postun
# Reload again so journalctl etc. drop the dead unit reference.
systemctl daemon-reload || :

%files
%attr(0755, root, root)             /usr/bin/openwatch
%dir %attr(0750, root, openwatch)   /etc/openwatch
# TLS dir ships empty (0750); %post generates the demo cert/key into it
# generate-if-absent. The cert/key files are intentionally NOT packaged, so
# a package upgrade cannot revert an operator's replacement certificate.
# They are declared %ghost — rpm tracks the paths (no payload content, nothing
# laid down or verified) so that on an upgrade FROM a release that DID ship the
# cert (<= rc.9), rpm does not reclaim/erase the operator's file as an orphan.
%dir %attr(0750, root, openwatch)   /etc/openwatch/tls
%ghost %attr(0644, root, openwatch)      /etc/openwatch/tls/cert.pem
%ghost %attr(0600, openwatch, openwatch) /etc/openwatch/tls/key.pem
%config(noreplace) %attr(0640, root, openwatch) /etc/openwatch/openwatch.toml
%config(noreplace) %attr(0640, root, openwatch) /etc/openwatch/upgrade.conf
%attr(0644, root, root)             /etc/systemd/system/openwatch.service
%attr(0644, root, root)             /etc/systemd/system/openwatch-backup-cleanup.service
%attr(0644, root, root)             /etc/systemd/system/openwatch-backup-cleanup.timer
# Identity-key directory ships empty (0750); %post generates the per-install
# keys into it. The key files are intentionally NOT packaged.
%dir %attr(0750, root, openwatch)   /etc/openwatch/keys
%attr(0755, root, root)             /usr/lib/openwatch/provision-identity-keys.sh
%attr(0755, root, root)             /usr/lib/openwatch/provision-tls-cert.sh
%attr(0755, root, root)             /usr/lib/openwatch/openwatch-upgrade.sh
%attr(0755, root, root)             /usr/lib/openwatch/cleanup-backups.sh
%dir %attr(0750, openwatch, openwatch) /var/lib/openwatch
%dir %attr(0750, root, openwatch)   /var/lib/openwatch/backups
%dir %attr(0750, openwatch, openwatch) /var/log/openwatch

%changelog
* Sun May 24 2026 OpenWatch Build <build@hanalyx.com> - 0.1.0-1
- Initial Stage-0 native RPM (Go binary).
