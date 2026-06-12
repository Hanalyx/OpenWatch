// @spec system-kensa-executor
//
// Production ScanFunc mapping + factory-connect tests:
//
//	AC-01  TestRefsToMap_PreservesEveryControl / TestMapOutcomes_FieldCopy
//	AC-18  TestProductionBinding_SourceInspection
//	AC-22  TestConnect_ValidationPaths / TestEffectiveCredAndSudo
package kensa

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	kensaapi "github.com/Hanalyx/kensa/api"
	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/credential"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
)

// @ac AC-01
func TestRefsToMap_PreservesEveryControl(t *testing.T) {
	t.Run("system-kensa-executor/AC-01", func(t *testing.T) {
		got := refsToMap([]kensaapi.FrameworkRef{
			{FrameworkID: "nist_800_53_r5", ControlID: "AC-6(2)"},
			{FrameworkID: "nist_800_53_r5", ControlID: "AC-17(2)"},
			{FrameworkID: "nist_800_53_r5", ControlID: "IA-2(5)"},
			{FrameworkID: "cis_rhel9_v2", ControlID: "5.1.20"},
		})
		if len(got["nist_800_53_r5"]) != 3 {
			t.Errorf("NIST controls = %v, want all 3 preserved", got["nist_800_53_r5"])
		}
		if len(got["cis_rhel9_v2"]) != 1 || got["cis_rhel9_v2"][0] != "5.1.20" {
			t.Errorf("CIS controls = %v", got["cis_rhel9_v2"])
		}
		if refsToMap(nil) != nil {
			t.Error("empty refs must map to nil (rule belongs to no framework)")
		}
	})
}

// @ac AC-01
func TestMapOutcomes_FieldCopy(t *testing.T) {
	t.Run("system-kensa-executor/AC-01", func(t *testing.T) {
		in := []kensaapi.RuleOutcome{
			{RuleID: "ssh-disable-root-login", Status: kensaapi.CompliancePass,
				Severity: "high", Detail: "permitrootlogin no",
				FrameworkRefs: []kensaapi.FrameworkRef{{FrameworkID: "cis_rhel9_v2", ControlID: "5.1.20"}}},
			{RuleID: "fw-enabled", Status: kensaapi.ComplianceFail, Severity: "high", Detail: "ufw inactive"},
			{RuleID: "no-default-impl", Status: kensaapi.ComplianceSkipped, Detail: "no implementation matched"},
			{RuleID: "broken", Status: kensaapi.ComplianceError, Err: errors.New("transport flake")},
			{RuleID: "future", Status: kensaapi.ComplianceStatus("quarantined")}, // defensive: unknown enum
		}
		out := mapOutcomes(in)
		if len(out) != 5 {
			t.Fatalf("len = %d, want 5 (every outcome recorded)", len(out))
		}
		if out[0].Status != StatusPass || out[0].Severity != "high" ||
			len(out[0].FrameworkRefs["cis_rhel9_v2"]) != 1 {
			t.Errorf("pass outcome mangled: %+v", out[0])
		}
		if !strings.Contains(string(out[0].Evidence), "permitrootlogin no") {
			t.Errorf("evidence lost detail: %s", out[0].Evidence)
		}
		if out[1].Status != StatusFail {
			t.Errorf("fail -> %s", out[1].Status)
		}
		if out[2].Status != StatusSkipped || out[2].SkipReason != "no implementation matched" {
			t.Errorf("skip mapping: %+v", out[2])
		}
		if out[3].Status != StatusError || !strings.Contains(string(out[3].Evidence), "transport flake") {
			t.Errorf("error mapping: %+v", out[3])
		}
		// Unknown future status degrades to error — never a fabricated verdict.
		if out[4].Status != StatusError {
			t.Errorf("unknown enum -> %s, want error", out[4].Status)
		}
	})
}

// @ac AC-22
func TestConnect_ValidationPaths(t *testing.T) {
	t.Run("system-kensa-executor/AC-22", func(t *testing.T) {
		ctx := context.Background()

		// Nil resolver errors before anything else.
		f := &TransportFactory{}
		if _, err := f.Connect(ctx, kensaapi.HostConfig{FleetID: uuid.NewString()}); err == nil {
			t.Error("nil resolver must error")
		}

		// Malformed FleetID errors before the resolver is consulted.
		resolverCalled := false
		f = &TransportFactory{Resolve: func(context.Context, uuid.UUID) (*credential.Credential, error) {
			resolverCalled = true
			return nil, errors.New("unreachable")
		}}
		if _, err := f.Connect(ctx, kensaapi.HostConfig{FleetID: "not-a-uuid"}); err == nil {
			t.Error("malformed FleetID must error")
		}
		if resolverCalled {
			t.Error("resolver consulted despite malformed FleetID")
		}

		// Resolver failure is wrapped and surfaced.
		f = &TransportFactory{Resolve: func(context.Context, uuid.UUID) (*credential.Credential, error) {
			return nil, errors.New("vault sealed")
		}}
		if _, err := f.Connect(ctx, kensaapi.HostConfig{FleetID: uuid.NewString()}); err == nil ||
			!strings.Contains(err.Error(), "vault sealed") {
			t.Errorf("resolver error not surfaced: %v", err)
		}
	})
}

// @ac AC-22
func TestEffectiveCredAndSudo(t *testing.T) {
	t.Run("system-kensa-executor/AC-22", func(t *testing.T) {
		base := &credential.Credential{Username: "svcacct"}

		// No override: same object, sudo preserved.
		cred, sudo := effectiveCredAndSudo(base, kensaapi.HostConfig{Sudo: true})
		if cred != base || !sudo {
			t.Errorf("no-override: cred=%p sudo=%v", cred, sudo)
		}

		// Override: copy, original untouched.
		cred, sudo = effectiveCredAndSudo(base, kensaapi.HostConfig{User: "scanner", Sudo: true})
		if cred == base {
			t.Error("override must copy, not mutate the cached credential")
		}
		if cred.Username != "scanner" || base.Username != "svcacct" {
			t.Errorf("override result %q / base %q", cred.Username, base.Username)
		}
		if !sudo {
			t.Error("non-root override must preserve sudo")
		}

		// Root (via override) downgrades sudo.
		_, sudo = effectiveCredAndSudo(base, kensaapi.HostConfig{User: "root", Sudo: true})
		if sudo {
			t.Error("root user must downgrade sudo to false")
		}

		// Root (credential's own user) downgrades too.
		rootCred := &credential.Credential{Username: "root"}
		_, sudo = effectiveCredAndSudo(rootCred, kensaapi.HostConfig{Sudo: true})
		if sudo {
			t.Error("root credential must downgrade sudo to false")
		}
	})
}

// @ac AC-18
// The production chain is fully bound (v2.3.0 C-13): scanfunc.go
// composes the scan-only Kensa via api.New + pkg/kensa.NewScanner over
// this package's TransportFactory, and the worker subcommand binds it
// through WithScanFunc(NewProductionScanFunc).
func TestProductionBinding_SourceInspection(t *testing.T) {
	t.Run("system-kensa-executor/AC-18", func(t *testing.T) {
		scanfunc := mustReadFile(t, filepath.Join(pkgDir(t), "scanfunc.go"))
		for _, needle := range []string{
			"pkgkensa.NewScanner()",
			"kensaapi.New(kensaapi.Config{",
			"TransportFactory: factory",
		} {
			if !strings.Contains(scanfunc, needle) {
				t.Errorf("scanfunc.go missing %q — production composition per C-13", needle)
			}
		}

		workerSrc := mustReadFile(t, filepath.Join(pkgDir(t), "..", "..", "cmd", "openwatch", "worker.go"))
		for _, needle := range []string{
			"kensa.NewProductionScanFunc(",
			".WithScanFunc(scanFn)",
		} {
			if !strings.Contains(workerSrc, needle) {
				t.Errorf("cmd/openwatch/worker.go missing %q — the worker must bind the production ScanFunc", needle)
			}
		}
	})
}

// @ac AC-23
// Air-gap corpus policy (C-16): production resolves rules from the
// signed kensa-rules package at the loader's default path; the env
// override is development-only and both boot paths must warn when it
// is set, so the shortcut cannot creep into a production runbook.
func TestRulesDirOverride_WarnedDevOnly_SourceInspection(t *testing.T) {
	t.Run("system-kensa-executor/AC-23", func(t *testing.T) {
		for _, f := range []string{"main.go", "worker.go"} {
			src := mustReadFile(t, filepath.Join(pkgDir(t), "..", "..", "cmd", "openwatch", f))
			if !strings.Contains(src, "OPENWATCH_KENSA_RULES_DIR") {
				continue // file doesn't wire scans (defensive)
			}
			if !strings.Contains(src, "DEVELOPMENT ONLY") {
				t.Errorf("cmd/openwatch/%s reads OPENWATCH_KENSA_RULES_DIR without the DEVELOPMENT ONLY warning (C-16)", f)
			}
			if !strings.Contains(src, "kensa-rules package") {
				t.Errorf("cmd/openwatch/%s warning must point operators at the signed kensa-rules package (C-16)", f)
			}
		}
		// ScanFuncDeps documents the packaged default path for empty RulesDir.
		scanfunc := mustReadFile(t, filepath.Join(pkgDir(t), "scanfunc.go"))
		if !strings.Contains(scanfunc, "kensa-rules") {
			t.Error("ScanFuncDeps.RulesDir doc must reference the kensa-rules package default (C-16)")
		}
	})
}

// classifyScanError: closed-enum mapping for dial-path failures.
func TestClassifyScanError(t *testing.T) {
	cases := []struct {
		err  error
		want FailureReason
	}{
		{owssh.ErrHostKeyUnknown, ReasonHostKeyUnknown},
		{owssh.ErrHostKeyMismatch, ReasonHostKeyUnknown},
		{owssh.ErrDialTimeout, ReasonTimeout},
		{owssh.ErrConnect, ReasonKensaError},
		{owssh.ErrAuthFailed, ReasonKensaError},
		{errors.New("anything else"), ReasonKensaError},
	}
	for _, c := range cases {
		if got := classifyScanError(c.err); got != c.want {
			t.Errorf("classify(%v) = %s, want %s", c.err, got, c.want)
		}
	}
}
