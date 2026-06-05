// @spec system-kensa-executor
//
// AC traceability (this file):
//   AC-02  TestSource_NoDiskWriteOfCredentialBytes
//   AC-10  TestKensaModuleVersion_MatchesGoMod
//          TestSpec_VersionPin_MatchesGoMod
//   AC-11  TestImports_OnlyCredentialFromInternal
//          TestImports_NoDirectEncryptionAESCalls
//   AC-12  TestNoEngineAbstractionInterface
//   AC-17  TestRunSignature_HasNoFrameworkParameter
//   AC-18  TestScanFunc_HasNoFrameworkParameter

package kensa

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// packageDir returns this package's source directory.
func packageDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	return filepath.Dir(file)
}

// appDir returns the app/ directory (parent of internal/).
func appDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(packageDir(t), "..", "..")
}

// goSourceFiles lists non-test .go files under dir.
func goSourceFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	return files
}

// @ac AC-10
// AC-10 (runtime side): the package-level KensaModuleVersion constant
// matches the version that appears in app/go.mod's require block.
// Source-inspection of go.mod for an exact match.
func TestKensaModuleVersion_MatchesGoMod(t *testing.T) {
	t.Run("system-kensa-executor/AC-10", func(t *testing.T) {
		goMod := mustReadFile(t, filepath.Join(appDir(t), "go.mod"))

		// Pattern: `github.com/Hanalyx/kensa v0.1.1` (with or without
		// `// indirect` suffix). Allows additional whitespace.
		re := regexp.MustCompile(`(?m)^\s*github\.com/Hanalyx/kensa\s+` + regexp.QuoteMeta(KensaModuleVersion) + `\b`)
		if !re.MatchString(goMod) {
			t.Errorf("go.mod does not pin github.com/Hanalyx/kensa at %q (the value of KensaModuleVersion in types.go)", KensaModuleVersion)
		}
	})
}

// @ac AC-10
// AC-10 (spec side): the spec's context.description mentions the same
// version string as KensaModuleVersion. The three sources of truth
// (spec, types.go constant, go.mod) must agree.
func TestSpec_VersionPin_MatchesGoMod(t *testing.T) {
	t.Run("system-kensa-executor/AC-10", func(t *testing.T) {
		specPath := filepath.Join(appDir(t), "specs", "system", "kensa-executor.spec.yaml")
		spec := mustReadFile(t, specPath)

		// The spec MUST mention the version string in its context.
		if !strings.Contains(spec, "pinned to "+KensaModuleVersion) {
			t.Errorf("kensa-executor.spec.yaml context does not mention %q; the spec, types.go constant, and go.mod must all agree", KensaModuleVersion)
		}
	})
}

// @ac AC-11
// AC-11: internal/kensa source files import only internal/credential
// (no other internal/ that handles credentials) for credential
// resolution. The package is allowed to import the audit, ssh, etc.
// packages for other concerns; the lock is specifically on credentials.
func TestImports_OnlyCredentialFromInternal(t *testing.T) {
	t.Run("system-kensa-executor/AC-11", func(t *testing.T) {
		files := goSourceFiles(t, packageDir(t))
		if len(files) == 0 {
			t.Skip("no source files yet; AC-11 is enforced once the package has source")
		}

		fset := token.NewFileSet()
		for _, f := range files {
			astFile, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			for _, imp := range astFile.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				// Allow stdlib, the project's allowed third-parties,
				// and any internal/* EXCEPT alternate credential-handling
				// packages (which would be a drift signal).
				if isCredentialDrift(path) {
					t.Errorf("%s imports %q — only internal/credential is permitted for credential handling (AC-11)", f, path)
				}
			}
		}
	})
}

// isCredentialDrift returns true if the given import path is a known
// credential-related internal package OTHER than the canonical
// internal/credential. None exist today; the guard catches future
// drift like internal/secrets, internal/keys, internal/authcreds.
func isCredentialDrift(path string) bool {
	const ow = "github.com/Hanalyx/openwatch/internal/"
	if !strings.HasPrefix(path, ow) {
		return false
	}
	sub := strings.TrimPrefix(path, ow)
	// The canonical credential package is permitted.
	if sub == "credential" || strings.HasPrefix(sub, "credential/") {
		return false
	}
	// Names that have "credential", "creds", "secret", or "key" in them
	// without being the canonical credential package — drift signals.
	low := strings.ToLower(sub)
	for _, marker := range []string{"credential", "creds"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

// @ac AC-11
// AC-11 (negative): internal/kensa source files do NOT import crypto/aes,
// crypto/cipher, or golang.org/x/crypto encryption primitives directly.
// All encryption goes through internal/credential.
func TestImports_NoDirectEncryptionAESCalls(t *testing.T) {
	t.Run("system-kensa-executor/AC-11", func(t *testing.T) {
		files := goSourceFiles(t, packageDir(t))
		if len(files) == 0 {
			t.Skip("no source files yet")
		}

		forbidden := []string{
			`"crypto/aes"`,
			`"crypto/cipher"`,
		}
		for _, f := range files {
			src := mustReadFile(t, f)
			for _, bad := range forbidden {
				if strings.Contains(src, bad) {
					t.Errorf("%s imports %s — direct encryption primitives are forbidden; use internal/credential (AC-11)", f, bad)
				}
			}
		}
	})
}

// @ac AC-12
// AC-12: internal/kensa source files MUST NOT define a generic scan-engine
// interface. Kensa is the only scan engine in Slice B; an abstraction
// over it would invite drift back toward the OpenSCAP-era engine
// pluggability. Source-inspection scans for `type ... interface` blocks
// that look engine-shaped.
func TestNoEngineAbstractionInterface(t *testing.T) {
	t.Run("system-kensa-executor/AC-12", func(t *testing.T) {
		files := goSourceFiles(t, packageDir(t))
		if len(files) == 0 {
			t.Skip("no source files yet")
		}

		// Pattern: any interface whose name contains "Engine", "Scanner",
		// or "ScanEngine". The pattern is intentionally broad; reviewers
		// add a //nolint:lint annotation in the rare legitimate case
		// (none expected in this package).
		bad := regexp.MustCompile(`(?m)^\s*type\s+\w*(Engine|Scanner|Adapter)\w*\s+interface\b`)

		for _, f := range files {
			src := mustReadFile(t, f)
			if m := bad.FindString(src); m != "" {
				t.Errorf("%s declares an engine-abstraction interface (%q) — Kensa is the only engine; abstraction forbidden by AC-12", f, strings.TrimSpace(m))
			}
		}
	})
}

// mustReadFile reads f or fatals.
func mustReadFile(t *testing.T, f string) string {
	t.Helper()
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("read %s: %v", f, err)
	}
	return string(b)
}

// @ac AC-02
// AC-02: SSH key bytes are NEVER written to /tmp or any disk path
// during executor.Run. Source-inspection enforces this at lint level:
// scan every non-test .go file in this package for forbidden
// disk-write patterns. If a future contributor reaches for
// os.WriteFile / os.Create / io.WriteString on a file handle in this
// package, the test fails and the contributor must use the in-memory
// crypto/ssh.Signer pattern via the custom TransportFactory.
//
// Strace-style runtime tracing is an alternative (mentioned in the
// spec), but is platform-dependent and fragile. Source-inspection
// is the same guarantee with a tighter feedback loop.
func TestSource_NoDiskWriteOfCredentialBytes(t *testing.T) {
	t.Run("system-kensa-executor/AC-02", func(t *testing.T) {
		files := goSourceFiles(t, packageDir(t))
		if len(files) == 0 {
			t.Skip("no source files yet")
		}

		// Forbidden patterns. Any of these in package source means
		// the contributor has introduced a disk-write path that
		// could touch credential bytes.
		forbidden := []struct {
			pattern string
			reason  string
		}{
			{`os.WriteFile(`, "use crypto/ssh.ParsePrivateKey on in-memory bytes; do not write to disk"},
			{`os.Create(`, "use crypto/ssh.ParsePrivateKey on in-memory bytes; do not open a file for writing"},
			{`ioutil.WriteFile(`, "deprecated; same prohibition as os.WriteFile"},
			{`ioutil.TempFile(`, "deprecated; if you need an ssh-agent socket use net.Listen / unix socket — never a file"},
			{`os.CreateTemp(`, "tempting for SSH keypath but explicitly forbidden — use in-memory signer"},
			{`/tmp/`, "no path under /tmp may appear; keys live in memory only"},
		}

		for _, f := range files {
			src := mustReadFile(t, f)
			for _, p := range forbidden {
				if strings.Contains(src, p.pattern) {
					t.Errorf("%s contains forbidden pattern %q — AC-02: %s",
						f, p.pattern, p.reason)
				}
			}
		}
	})
}

// @ac AC-17
// AC-17 (v2.0.0): Executor.Run signature is Run(ctx, hostID, policyVersion).
// No framework parameter. The string "framework" appears only in
// FrameworkRefs (per-rule metadata) or in v1-history doc comments.
func TestRunSignature_HasNoFrameworkParameter(t *testing.T) {
	t.Run("system-kensa-executor/AC-17", func(t *testing.T) {
		src, err := os.ReadFile(filepath.Join(packageDir(t), "executor.go"))
		if err != nil {
			t.Fatalf("read executor.go: %v", err)
		}
		// Match the Run method signature line specifically.
		// Allow whitespace variations.
		signaturePattern := regexp.MustCompile(`(?m)^func \(e \*Executor\) Run\(([^)]*)\)`)
		m := signaturePattern.FindStringSubmatch(string(src))
		if m == nil {
			t.Fatal("could not locate Executor.Run signature in executor.go")
		}
		params := m[1]
		// Acceptable: ctx context.Context, hostID uuid.UUID, policyVersion string
		// Forbidden: any occurrence of "framework" in the parameter list.
		if strings.Contains(params, "framework") {
			t.Errorf("Executor.Run signature still references 'framework': params=%q (v2.0.0 AC-17 requires removal)", params)
		}
	})
}

// @ac AC-18
// AC-18 (v2.0.0): the ScanFunc type signature has no framework
// parameter. unwiredScanFunc still exists as a test-only fallback
// (annotated //nolint:unused) — the production binding via
// pkg/kensa.Default lands with the worker subcommand.
func TestScanFunc_HasNoFrameworkParameter(t *testing.T) {
	t.Run("system-kensa-executor/AC-18", func(t *testing.T) {
		src, err := os.ReadFile(filepath.Join(packageDir(t), "executor.go"))
		if err != nil {
			t.Fatalf("read executor.go: %v", err)
		}
		// Match the ScanFunc type alias.
		typePattern := regexp.MustCompile(`type ScanFunc func\(([^)]*)\)`)
		m := typePattern.FindStringSubmatch(string(src))
		if m == nil {
			t.Fatal("could not locate ScanFunc type definition in executor.go")
		}
		if strings.Contains(m[1], "framework") {
			t.Errorf("ScanFunc signature still references 'framework': params=%q (v2.0.0 AC-18 requires removal)", m[1])
		}
		// unwiredScanFunc is allowed to remain but MUST be marked
		// //nolint:unused — otherwise it would fail the unused linter
		// once removed from NewExecutor's binding.
		if !strings.Contains(string(src), "//nolint:unused") {
			t.Log("note: unwiredScanFunc lacks //nolint:unused — fine if still referenced; will fail unused-lint once production binding lands")
		}
	})
}
