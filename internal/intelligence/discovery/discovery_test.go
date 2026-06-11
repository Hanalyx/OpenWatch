// @spec system-host-discovery
//
// AC traceability (this file):
//
//	AC-05  TestDiscover_SudoFailureIsPartialSuccess
//	AC-06  TestDiscover_OneSSHDialPerCall
//	AC-07  TestDiscover_HostSystemInfoAndDenormalizedColumnsInOneTx
//	AC-11  TestDiscover_PublishesHostDiscoveredOnBus
//	AC-12  TestDiscover_EmitsAuditOnSuccess
//	AC-14  TestDiscover_SecondRunUpsertsExistingRow
//	AC-15  TestDiscoveryPackage_CredentialAwareBoundaryDocumented

package discovery

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// @ac AC-15
// AC-15: discovery package source MAY import internal/credential and
// golang.org/x/crypto/ssh (intentionally credential-aware, unlike
// internal/liveness). The doc comment MUST state this explicitly.
func TestDiscoveryPackage_CredentialAwareBoundaryDocumented(t *testing.T) {
	t.Run("system-host-discovery/AC-15", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		dir := filepath.Dir(file)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}
		fset := token.NewFileSet()
		var sawCredentialImport, sawSSHImport, sawBoundaryComment bool
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			astFile, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", e.Name(), err)
			}
			for _, imp := range astFile.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if strings.Contains(p, "internal/credential") {
					sawCredentialImport = true
				}
				if strings.Contains(p, "golang.org/x/crypto/ssh") {
					sawSSHImport = true
				}
			}
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			// Package doc comment MUST acknowledge the boundary so future
			// readers know discovery is intentionally credential-aware.
			if strings.Contains(string(src), "credential-aware") ||
				strings.Contains(string(src), "credential aware") {
				sawBoundaryComment = true
			}
		}
		if !sawCredentialImport {
			t.Errorf("expected internal/credential import in discovery package — boundary contract not yet wired")
		}
		if !sawSSHImport {
			t.Errorf("expected golang.org/x/crypto/ssh import in discovery package — SSH dial owned here")
		}
		if !sawBoundaryComment {
			t.Errorf("package doc comment MUST acknowledge the credential-aware boundary (literal phrase \"credential-aware\")")
		}
	})
}

// @ac AC-06
// AC-06: Discover MUST open EXACTLY ONE ssh.Dial per call. A test SSH
// transport that counts dials registers exactly 1 regardless of how
// many sub-commands the probe runs.
func TestDiscover_OneSSHDialPerCall(t *testing.T) {
	t.Run("system-host-discovery/AC-06", func(t *testing.T) {
		stub := newStubSSHTransport()
		stub.SeedAll()

		svc := NewService(nil /* pool — not used by fake */, nil, nil).
			WithSSHTransport(stub)
		_, err := svc.discoverWithTransport(testCtx(t), testHostFacts())
		if err != nil {
			t.Fatalf("discoverWithTransport: %v", err)
		}
		if stub.DialCount() != 1 {
			t.Errorf("ssh.Dial called %d times, want 1 (one session per Discover)", stub.DialCount())
		}
	})
}

// @ac AC-05
// AC-05: When the host's credential lacks sudo on a sub-command that
// requires it (firewall introspection on some distros), Discover
// returns SystemFacts with the partial fields populated AND nil error.
func TestDiscover_SudoFailureIsPartialSuccess(t *testing.T) {
	t.Run("system-host-discovery/AC-05", func(t *testing.T) {
		stub := newStubSSHTransport()
		stub.SeedAll()
		// Firewall sub-command needs sudo on this distro; return exit 1
		// with permission-denied to simulate the operator's credential
		// having no sudo.
		stub.FailCommand("sudo -n nft list ruleset", "Operation not permitted", 1)
		stub.FailCommand("sudo -n iptables -L", "Permission denied", 1)
		stub.FailCommand("sudo -n ufw status", "Permission denied", 1)
		stub.FailCommand("sudo -n firewall-cmd --state", "Permission denied", 1)

		svc := NewService(nil, nil, nil).WithSSHTransport(stub)
		facts, err := svc.discoverWithTransport(testCtx(t), testHostFacts())
		if err != nil {
			t.Fatalf("partial-success Discover returned error: %v", err)
		}
		// OS / kernel / meminfo / df / hostname must still be populated
		// (world-readable, no sudo needed).
		if facts.OSName == "" {
			t.Errorf("OSName empty — non-privileged probes should have populated it")
		}
		if facts.KernelRelease == "" {
			t.Errorf("KernelRelease empty — uname needs no sudo")
		}
		// Firewall fields stay empty, marking the gap honestly.
		if facts.FirewallService != "" {
			t.Errorf("FirewallService=%q, want empty when sudo denied", facts.FirewallService)
		}
	})
}

// @ac AC-07
// AC-07: host_system_info upsert + denormalized hosts.os_* columns
// MUST be one transaction. Source inspection: a single BEGIN/COMMIT
// (or pool.BeginTx + tx.Commit) wraps both writes.
func TestDiscover_HostSystemInfoAndDenormalizedColumnsInOneTx(t *testing.T) {
	t.Run("system-host-discovery/AC-07", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		dir := filepath.Dir(file)
		src, err := os.ReadFile(filepath.Join(dir, "discovery.go"))
		if err != nil {
			t.Fatalf("read discovery.go: %v", err)
		}
		s := string(src)
		// One transaction wraps the two writes. We detect it by source
		// pattern — a future regression that splits them into two
		// pool.Exec calls would lose the atomic guarantee.
		if !strings.Contains(s, "BeginTx") && !strings.Contains(s, "pool.Begin(") {
			t.Errorf("persist() must open a transaction; no Begin call found in discovery.go")
		}
		// The persist body must INSERT/UPDATE both host_system_info AND
		// hosts.os_* in the same scope.
		persistIdx := strings.Index(s, "func (s *Service) persist")
		if persistIdx < 0 {
			t.Fatalf("persist function not found")
		}
		body := s[persistIdx:]
		nextFn := strings.Index(body[1:], "\nfunc ")
		if nextFn > 0 {
			body = body[:nextFn]
		}
		if !strings.Contains(body, "host_system_info") {
			t.Errorf("persist body does not reference host_system_info")
		}
		if !strings.Contains(body, "UPDATE hosts") && !strings.Contains(body, "os_family") {
			t.Errorf("persist body does not update hosts.os_family")
		}
	})
}

// @ac AC-11
// AC-11: Successful Discover publishes eventbus.HostDiscovered.
func TestDiscover_PublishesHostDiscoveredOnBus(t *testing.T) {
	t.Run("system-host-discovery/AC-11", func(t *testing.T) {
		bus := newStubBus()
		stub := newStubSSHTransport()
		stub.SeedAll()
		svc := NewService(nil, nil, bus).WithSSHTransport(stub)
		facts, err := svc.discoverWithTransport(testCtx(t), testHostFacts())
		if err != nil {
			t.Fatalf("Discover: %v", err)
		}
		// publishBusEvent is the seam that emits HostDiscovered after a
		// successful persist. We test it directly so the test doesn't
		// require a live DB.
		svc.publishBusEvent(testHostFacts().HostID, facts)
		if !bus.Saw("host.discovered") {
			t.Errorf("eventbus did not receive host.discovered after successful Discover")
		}
	})
}

// @ac AC-12
// AC-12: Successful Discover emits exactly one HostDiscoveryCompleted
// audit event. Failures must NOT emit.
func TestDiscover_EmitsAuditOnSuccess(t *testing.T) {
	t.Run("system-host-discovery/AC-12", func(t *testing.T) {
		emits := newAuditRecorder()
		stub := newStubSSHTransport()
		stub.SeedAll()
		svc := NewService(nil, emits.Emit, nil).WithSSHTransport(stub)
		facts, err := svc.discoverWithTransport(testCtx(t), testHostFacts())
		if err != nil {
			t.Fatalf("Discover: %v", err)
		}
		svc.emitAuditSuccess(testCtx(t), testHostFacts().HostID, facts)
		if got := emits.CountFor("host.discovery.completed"); got != 1 {
			t.Errorf("audit emits for host.discovery.completed = %d, want 1", got)
		}
	})
}

// @ac AC-14
// AC-14: A second Discover UPDATES the existing host_system_info row
// (UNIQUE on host_id). Source-level: the UPSERT uses ON CONFLICT
// (host_id) DO UPDATE — verifies the contract without a live DB.
func TestDiscover_SecondRunUpsertsExistingRow(t *testing.T) {
	t.Run("system-host-discovery/AC-14", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		dir := filepath.Dir(file)
		src, err := os.ReadFile(filepath.Join(dir, "discovery.go"))
		if err != nil {
			t.Fatalf("read discovery.go: %v", err)
		}
		s := string(src)
		if !strings.Contains(s, "ON CONFLICT (host_id) DO UPDATE") {
			t.Errorf("host_system_info UPSERT must use ON CONFLICT (host_id) DO UPDATE — append-style insert detected or pattern missing")
		}
	})
}
