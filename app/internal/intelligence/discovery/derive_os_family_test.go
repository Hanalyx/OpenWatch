// @spec system-host-discovery
//
// AC traceability (this file):
//
//   AC-22  TestDeriveOSFamily_PrefersOSID
//   AC-22  TestDeriveOSFamily_FallsBackToIDLikeWhenIDEmpty
//   AC-22  TestDeriveOSFamily_OtherWhenNothingRecognized

package discovery

import "testing"

// @ac AC-22
// AC-22 (primary): /etc/os-release's ID is the canonical distro
// identifier and MUST be persisted verbatim (lower-cased) into
// hosts.os_family. Collapsing Ubuntu to "debian" via ID_LIKE was a
// regression — the front-end's osDisplayLabel mapping at
// frontend-host-list-os AC-01..AC-03 expects the distro ID so it can
// render "Ubuntu" vs "Debian" vs "Rocky" separately.
func TestDeriveOSFamily_PrefersOSID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		like string
		want string
	}{
		// The regression: pre-fix, Ubuntu collapsed to "debian".
		{"ubuntu-debian-like", "ubuntu", "debian", "ubuntu"},
		{"ubuntu-no-id-like", "ubuntu", "", "ubuntu"},

		// Existing well-formed mappings — verifies the change doesn't
		// silently re-route these.
		{"rhel", "rhel", "fedora", "rhel"},
		{"debian-only", "debian", "", "debian"},
		{"rocky", "rocky", "rhel fedora", "rocky"},
		{"centos", "centos", "rhel fedora", "centos"},
		{"almalinux", "almalinux", "rhel centos fedora", "almalinux"},

		// SUSE family — the front-end maps opensuse + sles directly.
		{"opensuse-leap", "opensuse-leap", "suse opensuse", "opensuse-leap"},
		{"sles", "sles", "suse", "sles"},

		// Case folding + whitespace tolerance.
		{"upper-case", "Ubuntu", "Debian", "ubuntu"},
		{"padded", "  rocky  ", "rhel", "rocky"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveOSFamily(tc.id, tc.like)
			if got != tc.want {
				t.Errorf("deriveOSFamily(%q, %q) = %q, want %q", tc.id, tc.like, got, tc.want)
			}
		})
	}
}

// @ac AC-22
// AC-22 (fallback): an empty ID falls back to the first recognized
// rollup family from ID_LIKE. Lets minimal images that only export
// ID_LIKE still classify, instead of going straight to "other".
func TestDeriveOSFamily_FallsBackToIDLikeWhenIDEmpty(t *testing.T) {
	cases := []struct {
		name string
		id   string
		like string
		want string
	}{
		{"empty-id-debian-like", "", "debian", "debian"},
		{"empty-id-ubuntu-like", "", "ubuntu debian", "debian"}, // first recognized hit wins
		{"empty-id-rhel-like", "", "fedora", "rhel"},
		{"empty-id-suse-like", "", "suse opensuse", "suse"},
		{"empty-id-alpine-like", "", "alpine", "alpine"},
		{"empty-id-arch-like", "", "arch", "arch"},
		{"empty-id-gentoo-like", "", "gentoo", "gentoo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveOSFamily(tc.id, tc.like)
			if got != tc.want {
				t.Errorf("deriveOSFamily(%q, %q) = %q, want %q", tc.id, tc.like, got, tc.want)
			}
		})
	}
}

// @ac AC-22
// AC-22 (terminal default): when neither ID nor ID_LIKE produces a
// recognized family the result is the literal "other". The front-end
// mapping renders it as "Unknown".
func TestDeriveOSFamily_OtherWhenNothingRecognized(t *testing.T) {
	cases := []struct {
		name string
		id   string
		like string
	}{
		{"both-empty", "", ""},
		{"id-empty-like-unknown", "", "freedos"},
		{"id-empty-like-noise", "", "   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveOSFamily(tc.id, tc.like)
			if got != "other" {
				t.Errorf("deriveOSFamily(%q, %q) = %q, want %q", tc.id, tc.like, got, "other")
			}
		})
	}
}
