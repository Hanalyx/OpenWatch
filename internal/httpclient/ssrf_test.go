package httpclient

import (
	"net"
	"testing"
)

// TestBlockedIP covers the SSRF range classifier, including the CGNAT
// (100.64.0.0/10) and IPv4-mapped cases that net.IP.IsPrivate misses.
func TestBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"10.1.2.3", "192.168.0.1", "172.16.0.1", // RFC1918
		"169.254.169.254",    // link-local / cloud metadata
		"0.0.0.0",            // unspecified
		"100.64.0.1",         // CGNAT (the SEC-M1 gap)
		"100.127.255.254",    // CGNAT upper edge
		"::ffff:10.0.0.1",    // IPv4-mapped private
		"::ffff:169.254.1.1", // IPv4-mapped link-local
		"fc00::1",            // IPv6 ULA
	}
	for _, s := range blocked {
		if !BlockedIP(net.ParseIP(s)) {
			t.Errorf("BlockedIP(%s) = false, want true", s)
		}
	}
	if !BlockedIP(nil) {
		t.Error("BlockedIP(nil) = false, want true (fail closed)")
	}

	public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "100.63.255.255", "100.128.0.0"}
	for _, s := range public {
		if BlockedIP(net.ParseIP(s)) {
			t.Errorf("BlockedIP(%s) = true, want false", s)
		}
	}
}

func TestGuardedDialControl(t *testing.T) {
	if err := GuardedDialControl("tcp", "100.64.1.1:443", nil); err == nil {
		t.Error("GuardedDialControl(CGNAT) = nil, want block")
	}
	if err := GuardedDialControl("tcp", "10.0.0.1:443", nil); err == nil {
		t.Error("GuardedDialControl(private) = nil, want block")
	}
	if err := GuardedDialControl("tcp", "1.1.1.1:443", nil); err != nil {
		t.Errorf("GuardedDialControl(public) = %v, want nil", err)
	}
}

func TestBlockedHost(t *testing.T) {
	for _, h := range []string{"localhost", "foo.localhost", "127.0.0.1", "100.64.0.5"} {
		if !BlockedHost(h) {
			t.Errorf("BlockedHost(%s) = false, want true", h)
		}
	}
	if BlockedHost("example.com") {
		t.Error("BlockedHost(example.com) = true, want false")
	}
}
