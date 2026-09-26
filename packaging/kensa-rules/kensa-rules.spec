# kensa-rules: the Kensa compliance rule corpus, packaged separately from
# the OpenWatch binary.
#
# WHY a separate package: the kensa engine carries no embedded corpus and
# loads rules from /usr/share/kensa/rules at runtime. Shipping the corpus
# as its own noarch package (a) lets the rules update on their own cadence
# (new STIG/CIS revisions) without re-releasing OpenWatch, (b) keeps the
# Kensa project's compliance content on its own version line, and (c) is
# the install-time artifact OpenWatch's RPM declares a hard Requires on,
# so a corpus-less install fails fast instead of degrading at scan time.
#
# noarch: rules are plain YAML, identical on amd64 and aarch64.

%global debug_package %{nil}

# Version is the kensa module version (e.g. 0.4.3), injected by
# build-kensa-rules.sh via --define "kr_version X.Y.Z".
%{!?kr_version: %global kr_version 0.0.0}
%{!?kr_release: %global kr_release 1}

Name:           kensa-rules
Version:        %{kr_version}
Release:        %{kr_release}%{?dist}
Summary:        Kensa compliance rule corpus (native YAML rules)
BuildArch:      noarch

License:        Business Source License 1.1
URL:            https://github.com/Hanalyx/kensa
Source0:        %{name}-%{version}.tar.gz

# The corpus needs an engine at least as new as itself. Kensa v0.9.0 cannot
# load the v0.10.0 corpus at all, and OpenWatch starts anyway with every scan
# failing, so a rules-only upgrade beside an older openwatch is refused here.
# An older corpus under a newer engine loads, so only the floor is declared.
# The openwatch package provides openwatch-kensa-engine; releases before it
# provide nothing and so cannot satisfy this. Spec release-upgrade C-06.
Requires:       openwatch-kensa-engine >= %{version}

%description
The Kensa rule corpus: native YAML compliance rules consumed by the
Kensa scan engine embedded in OpenWatch. Installs to
/usr/share/kensa/rules, the engine's default rule-load path. This
package is versioned on the Kensa content line, independent of the
OpenWatch platform version, so rule updates ship without a platform
re-release.

%prep
%setup -q

%build
# Nothing to build — the corpus is staged by build-kensa-rules.sh.

%install
install -d -m 0755 %{buildroot}/usr/share/kensa/rules
cp -R rules/. %{buildroot}/usr/share/kensa/rules/
find %{buildroot}/usr/share/kensa/rules -type d -exec chmod 0755 {} +
find %{buildroot}/usr/share/kensa/rules -type f -exec chmod 0644 {} +

%files
%dir /usr/share/kensa
/usr/share/kensa/rules

%changelog
* Mon Jun 15 2026 OpenWatch Build <build@hanalyx.com> - 0.4.3-1
- Initial standalone Kensa rule-corpus package (539 rules, noarch).
