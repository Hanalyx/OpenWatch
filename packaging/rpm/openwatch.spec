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
Version:        %{ow_version}
Release:        %{ow_release}%{?dist}
Summary:        OpenWatch Compliance Platform (Go binary)

License:        Proprietary
URL:            https://github.com/Hanalyx/openwatch
Source0:        %{name}-%{version}.tar.gz

Requires:       postgresql-server
Requires(pre):  shadow-utils

%description
OpenWatch is the Go rebuild of the compliance scanning platform.
This package ships the single binary, default TOML config, embedded
demo TLS cert, and a hardened systemd unit. Operators replace
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
install -d -m 0750                  %{buildroot}/etc/openwatch/tls
install -m 0640 openwatch.toml      %{buildroot}/etc/openwatch/openwatch.toml
install -m 0644 cert.pem            %{buildroot}/etc/openwatch/tls/cert.pem
install -m 0600 key.pem             %{buildroot}/etc/openwatch/tls/key.pem

install -d -m 0755                  %{buildroot}/etc/systemd/system
install -m 0644 openwatch.service   %{buildroot}/etc/systemd/system/openwatch.service

install -d -m 0750                  %{buildroot}/var/lib/openwatch
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

%preun
# AC-09: stop and disable cleanly so removal doesn't leave a running orphan.
if [ $1 -eq 0 ]; then
    systemctl stop openwatch.service >/dev/null 2>&1 || :
    systemctl disable openwatch.service >/dev/null 2>&1 || :
fi

%postun
# Reload again so journalctl etc. drop the dead unit reference.
systemctl daemon-reload || :

%files
%attr(0755, root, root)             /usr/bin/openwatch
%dir %attr(0750, root, openwatch)   /etc/openwatch
%dir %attr(0750, root, openwatch)   /etc/openwatch/tls
%config(noreplace) %attr(0640, root, openwatch) /etc/openwatch/openwatch.toml
%attr(0644, root, openwatch)        /etc/openwatch/tls/cert.pem
%attr(0600, openwatch, openwatch)   /etc/openwatch/tls/key.pem
%attr(0644, root, root)             /etc/systemd/system/openwatch.service
%dir %attr(0750, openwatch, openwatch) /var/lib/openwatch
%dir %attr(0750, openwatch, openwatch) /var/log/openwatch

%changelog
* Sun May 24 2026 OpenWatch Build <build@hanalyx.com> - 0.1.0-1
- Initial Stage-0 native RPM (Go binary).
