// @spec system-os-intelligence
//
// AC traceability (this file):
//
//	AC-09  TestRunCycle_OneSSHDialPerCall
//	AC-10  TestRunCycle_SudoFailureIsPartialSuccess
//	AC-14  TestPersist_OnConflictDoesNotDuplicate
//	AC-15  TestMigration_HasClosedEnumCheckOnEventCode

package collector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// @ac AC-09
// AC-09: runCycleWithTransport opens EXACTLY ONE ssh.Dial per call.
func TestRunCycle_OneSSHDialPerCall(t *testing.T) {
	t.Run("system-os-intelligence/AC-09", func(t *testing.T) {
		stub := newStubSSHTransport()
		stub.SeedAll()

		svc := NewService(nil, nil, nil).WithSSHTransport(stub)
		_, _, err := svc.runCycleWithTransport(testCtx(t), testHostFacts())
		if err != nil {
			t.Fatalf("runCycleWithTransport: %v", err)
		}
		if stub.DialCount() != 1 {
			t.Errorf("ssh.Dial called %d times, want 1 (one session per cycle)", stub.DialCount())
		}
	})
}

// @ac AC-10
// AC-10: sudo failure on probe sub-commands (sha256sum /etc/shadow,
// sudo -n cat /etc/shadow) keeps the cycle returning nil + partial
// snapshot. Non-sudo categories still populate.
func TestRunCycle_SudoFailureIsPartialSuccess(t *testing.T) {
	t.Run("system-os-intelligence/AC-10", func(t *testing.T) {
		stub := newStubSSHTransport()
		stub.SeedAll()
		stub.FailCommand("sudo -n cat /etc/shadow", "Permission denied", 1)
		stub.FailCommand("sudo -n sha256sum /etc/shadow", "Permission denied", 1)

		svc := NewService(nil, nil, nil).WithSSHTransport(stub)
		snap, _, err := svc.runCycleWithTransport(testCtx(t), testHostFacts())
		if err != nil {
			t.Fatalf("partial-success cycle returned error: %v", err)
		}
		// Non-sudo data populated.
		if snap.KernelRelease == "" {
			t.Errorf("KernelRelease empty — uname needs no sudo")
		}
		if len(snap.Packages) == 0 {
			t.Errorf("Packages empty — rpm/dpkg needs no sudo")
		}
		// /etc/shadow hash MUST NOT be present (sudo denied).
		if _, has := snap.ConfigHashes["/etc/shadow"]; has {
			t.Errorf("/etc/shadow hash recorded despite sudo failure")
		}
	})
}

// @ac AC-14
// AC-14: source inspection — the events INSERT MUST use ON CONFLICT
// (host_id, event_code, occurred_at) DO NOTHING so retried RunCycles
// don't double-insert.
func TestPersist_OnConflictDoesNotDuplicate(t *testing.T) {
	t.Run("system-os-intelligence/AC-14", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "collector.go"))
		if err != nil {
			t.Fatalf("read collector.go: %v", err)
		}
		s := string(src)
		if !strings.Contains(s, "ON CONFLICT (host_id, event_code, occurred_at) DO NOTHING") {
			t.Errorf("persist() events INSERT must carry ON CONFLICT (host_id, event_code, occurred_at) DO NOTHING — idempotency under retry guaranteed by the constraint")
		}
	})
}

// @ac AC-15
// AC-15: migration 0018 carries a CHECK clause enumerating every
// taxonomy code. Source inspection: the file contains a CHECK on
// event_code AND every code in taxonomyCodes appears in the CHECK list.
func TestMigration_HasClosedEnumCheckOnEventCode(t *testing.T) {
	t.Run("system-os-intelligence/AC-15", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		// Walk up to app/internal/db/migrations.
		dir := filepath.Dir(file)
		var migPath string
		for i := 0; i < 8; i++ {
			cand := filepath.Join(dir, "db", "migrations", "0018_host_intelligence.sql")
			if _, err := os.Stat(cand); err == nil {
				migPath = cand
				break
			}
			dir = filepath.Dir(dir)
		}
		if migPath == "" {
			t.Fatalf("could not locate migration 0018")
		}
		src, err := os.ReadFile(migPath)
		if err != nil {
			t.Fatalf("read migration: %v", err)
		}
		s := string(src)
		if !strings.Contains(s, "CHECK (event_code IN (") {
			t.Errorf("migration 0018 missing CHECK on event_code — closed enum invariant unenforced at DB")
		}
		for _, code := range Codes() {
			if !strings.Contains(s, "'"+string(code)+"'") {
				t.Errorf("migration 0018 CHECK is missing taxonomy code %q", code)
			}
		}
	})
}

// @ac AC-11 (sanity — exercised end-to-end by collector_db_test.go)
// @ac AC-12 (sanity — exercised end-to-end by collector_db_test.go)
// publishEvent + emitAuditFor exercised here without DB so the unit
// tests catch logic regressions even if the integration tests can't
// run (no OPENWATCH_TEST_DSN).
func TestPublishAndAudit_NilBusOrEmit_NoPanic(t *testing.T) {
	svc := NewService(nil, nil, nil)
	svc.publishEvent(context.Background(), testHostFacts().HostID, Event{
		Code: CodeSystemPackageUpdated, Severity: "info",
		Detail: map[string]any{"name": "openssh"},
	})
	svc.emitAuditFor(context.Background(), testHostFacts().HostID,
		Event{Code: CodeSystemPackageUpdated, Severity: "info",
			Detail: map[string]any{"name": "openssh"}}, "test-corr-id")
}
