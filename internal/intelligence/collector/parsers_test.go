// @spec system-os-intelligence
//
// AC traceability (this file):
//
//	AC-03  TestParsePasswdShadow_LockedOutUsersFlagged
//	AC-16  TestParsePasswdShadow_PasswordAging
//	AC-04  TestParseListeningPorts_SsOutput
//	AC-05  TestParseInstalledPackages_RPMAndDPKG

package collector

import (
	"strings"
	"testing"
)

// @ac AC-03
// AC-03: passwd + shadow → AccountFacts; users with shadow.password_field
// starting with "!" or "*" are flagged locked.
func TestParsePasswdShadow_LockedOutUsersFlagged(t *testing.T) {
	t.Run("system-os-intelligence/AC-03", func(t *testing.T) {
		const passwd = `root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:alice:/home/alice:/bin/bash
bob:x:1001:1001:bob:/home/bob:/bin/bash
nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin`
		const shadow = `root:$6$abc$xyz:19000:0:99999:7:::
alice:!!:19500:0:99999:7:::
bob:$6$def$xyz:19500:0:99999:7:::
nobody:*:19500:0:99999:7:::`
		facts, err := ParsePasswdShadow([]byte(passwd), []byte(shadow))
		if err != nil {
			t.Fatalf("ParsePasswdShadow: %v", err)
		}
		if got := facts.Users["alice"].Locked; !got {
			t.Errorf("alice expected locked=true (shadow=!!), got %v", got)
		}
		if got := facts.Users["nobody"].Locked; !got {
			t.Errorf("nobody expected locked=true (shadow=*), got %v", got)
		}
		if got := facts.Users["root"].Locked; got {
			t.Errorf("root expected locked=false, got %v", got)
		}
		if facts.Users["bob"].UID != 1001 {
			t.Errorf("bob uid=%d, want 1001", facts.Users["bob"].UID)
		}
	})
}

// @ac AC-16
// AC-16: ParsePasswdShadow captures GECOS + shell from passwd and the
// password-aging fields (lstchg f3, max f5) from shadow; PasswordExpiresAt
// is derived only when a real policy is in force (max not 99999/unset) and
// the last-change date is known. A literal lstchg 0 is preserved (force
// change) distinctly from an empty field (nil).
func TestParsePasswdShadow_PasswordAging(t *testing.T) {
	t.Run("system-os-intelligence/AC-16", func(t *testing.T) {
		const passwd = `owadmin:x:1000:1000:OpenWatch Admin:/home/owadmin:/bin/bash
policyuser:x:1001:1001:Policy User,,,:/home/policyuser:/bin/bash
forced:x:1002:1002::/home/forced:/bin/sh`
		// owadmin: no policy (max 99999). policyuser: 90-day policy, lstchg
		// 19000. forced: lstchg 0 (must change), no max.
		const shadow = `owadmin:$6$a$b:19000:0:99999:7:::
policyuser:$6$c$d:19000:0:90:7:::
forced:$6$e$f:0:0:99999:7:::`
		facts, err := ParsePasswdShadow([]byte(passwd), []byte(shadow))
		if err != nil {
			t.Fatalf("ParsePasswdShadow: %v", err)
		}

		// GECOS + shell captured.
		if got := facts.Users["owadmin"].Gecos; got != "OpenWatch Admin" {
			t.Errorf("owadmin gecos=%q, want %q", got, "OpenWatch Admin")
		}
		if got := facts.Users["owadmin"].Shell; got != "/bin/bash" {
			t.Errorf("owadmin shell=%q, want /bin/bash", got)
		}

		// No policy (99999): MaxDays present but PolicyActive false, no expiry.
		ow := facts.Users["owadmin"]
		if ow.MaxDays == nil || *ow.MaxDays != 99999 {
			t.Errorf("owadmin max_days=%v, want 99999", ow.MaxDays)
		}
		if PasswordPolicyActive(ow.MaxDays) {
			t.Error("owadmin: 99999 must not be an active policy")
		}
		if ow.PasswordExpiresAt != nil {
			t.Errorf("owadmin PasswordExpiresAt=%v, want nil (no policy)", ow.PasswordExpiresAt)
		}

		// Active 90-day policy: expiry = epoch + (19000+90) days.
		pu := facts.Users["policyuser"]
		if !PasswordPolicyActive(pu.MaxDays) {
			t.Fatalf("policyuser: max=90 must be an active policy")
		}
		if pu.PasswordExpiresAt == nil {
			t.Fatal("policyuser PasswordExpiresAt=nil, want a date")
		}
		wantExp := shadowEpoch.AddDate(0, 0, 19000+90)
		if !pu.PasswordExpiresAt.Equal(wantExp) {
			t.Errorf("policyuser expiry=%v, want %v", pu.PasswordExpiresAt, wantExp)
		}

		// lstchg 0 preserved as non-nil zero (force change), not nil.
		fu := facts.Users["forced"]
		if fu.LastChangeDays == nil || *fu.LastChangeDays != 0 {
			t.Errorf("forced last_change_days=%v, want 0", fu.LastChangeDays)
		}
	})
}

// @ac AC-04
// AC-04: ss -tln output → []ListeningPort{protocol, address, port}.
func TestParseListeningPorts_SsOutput(t *testing.T) {
	t.Run("system-os-intelligence/AC-04", func(t *testing.T) {
		const sample = `State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port
LISTEN   0        128              0.0.0.0:22              0.0.0.0:*
LISTEN   0        100        127.0.0.1:25                0.0.0.0:*
LISTEN   0        511              0.0.0.0:443             0.0.0.0:*
LISTEN   0        128                 [::]:22                [::]:*`
		ports, err := ParseListeningPorts([]byte(sample))
		if err != nil {
			t.Fatalf("ParseListeningPorts: %v", err)
		}
		if len(ports) == 0 {
			t.Fatal("expected at least one listening port, got 0")
		}
		seen := map[int]bool{}
		for _, p := range ports {
			seen[p.Port] = true
		}
		for _, want := range []int{22, 25, 443} {
			if !seen[want] {
				t.Errorf("expected port %d in listening list", want)
			}
		}
		// Empty input must not error.
		empty, err := ParseListeningPorts(nil)
		if err != nil {
			t.Fatalf("empty input should not error: %v", err)
		}
		if len(empty) != 0 {
			t.Errorf("empty input yielded %d ports, want 0", len(empty))
		}
	})
}

// @ac AC-05
// AC-05: ParseInstalledPackages handles both RPM and DPKG conventions.
func TestParseInstalledPackages_RPMAndDPKG(t *testing.T) {
	t.Run("system-os-intelligence/AC-05", func(t *testing.T) {
		// rpm -qa --queryformat='%{NAME} %{VERSION}-%{RELEASE}\n'
		const rpmSample = `openssh 9.0p1-19
openssh-server 9.0p1-19
glibc 2.34-83.el9
`
		rpm, err := ParseInstalledPackages([]byte(rpmSample))
		if err != nil {
			t.Fatalf("ParseInstalledPackages rpm: %v", err)
		}
		if rpm["openssh"] != "9.0p1-19" {
			t.Errorf("rpm openssh=%q, want 9.0p1-19", rpm["openssh"])
		}
		if rpm["glibc"] != "2.34-83.el9" {
			t.Errorf("rpm glibc=%q", rpm["glibc"])
		}

		// dpkg -l output (slimmed to relevant lines).
		const dpkgSample = `Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name              Version          Architecture Description
+++-=================-================-============-==================================
ii  openssh-server    1:9.6p1-3        amd64        secure shell (SSH) server
ii  libc6             2.39-0ubuntu8.5  amd64        GNU C Library: Shared libraries
`
		// strings.TrimSpace happy-path so the parser works regardless of
		// trailing newlines.
		got, err := ParseInstalledPackages([]byte(strings.TrimSpace(dpkgSample)))
		if err != nil {
			t.Fatalf("ParseInstalledPackages dpkg: %v", err)
		}
		if got["openssh-server"] != "1:9.6p1-3" {
			t.Errorf("dpkg openssh-server=%q, want 1:9.6p1-3", got["openssh-server"])
		}
		if got["libc6"] != "2.39-0ubuntu8.5" {
			t.Errorf("dpkg libc6=%q", got["libc6"])
		}
	})
}
