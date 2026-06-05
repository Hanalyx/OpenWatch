// @spec system-daemon-orchestration
//
// AC traceability (this file):
//   AC-01  TestMainImportsSliceBPackages
//   AC-02  TestCmdServe_BootSequenceOrder
//   AC-03  TestCmdServe_ShutdownOrder
//   AC-04  TestCmdServe_RouterStartBeforeLivenessRun
//   AC-05  TestSliceBPackages_DoNotImportAuditEmit
//   AC-06  TestCmdServe_RegistersStdoutWildcardChannel
//   AC-08  TestCmdServe_DiscoveryServiceWired
//   AC-09  TestCmdServe_IntelligenceSchedulerWired
//   AC-10  TestCmdServe_MaintenancePauseWarnLog
//
// These tests are source-inspection — they read app/cmd/openwatch/main.go
// and the Slice B package directories and assert structural invariants.
// A runtime ordering test would need to refactor cmdServe to accept
// injected NewX wrappers; that lands when the spec next bumps to v1.1.0.

package main

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

func mainGoSource(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	return string(src)
}

// orderedContains reports whether all needles appear in src in the
// listed order (non-overlapping). Used by AC-02/03/04 to assert textual
// boot-sequence ordering.
func orderedContains(src string, needles []string) (int, string) {
	pos := 0
	for _, n := range needles {
		idx := strings.Index(src[pos:], n)
		if idx < 0 {
			return -1, n
		}
		pos += idx + len(n)
	}
	return pos, ""
}

// @ac AC-01
// AC-01: cmd/openwatch imports the Slice B packages it wires.
func TestMainImportsSliceBPackages(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-01", func(t *testing.T) {
		src := mainGoSource(t)
		for _, want := range []string{
			`"github.com/Hanalyx/openwatch/internal/alertrouter"`,
			`"github.com/Hanalyx/openwatch/internal/alertrouter/channels/stdout"`,
			`"github.com/Hanalyx/openwatch/internal/eventbus"`,
			`"github.com/Hanalyx/openwatch/internal/liveness"`,
		} {
			if !strings.Contains(src, want) {
				t.Errorf("main.go imports do not include %s", want)
			}
		}
	})
}

// @ac AC-02
// AC-02: cmdServe's textual boot sequence matches C-01.
func TestCmdServe_BootSequenceOrder(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-02", func(t *testing.T) {
		src := mainGoSource(t)
		seq := []string{
			"eventbus.NewBus",
			"alertrouter.NewRouter",
			"router.Register",
			"router.Start",
			"liveness.NewService",
			"liveSvc.Run",
			"server.New",
			"srv.Run",
		}
		if _, missing := orderedContains(src, seq); missing != "" {
			t.Errorf("boot sequence broken — could not find %q after the preceding step", missing)
		}
	})
}

// @ac AC-03
// AC-03: router.Stop appears AFTER srv.Run; bus.Shutdown is deferred
// BEFORE alertrouter is constructed (so its defer runs after router.Stop).
func TestCmdServe_ShutdownOrder(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-03", func(t *testing.T) {
		src := mainGoSource(t)
		idxSrvRun := strings.Index(src, "srv.Run(ctx)")
		idxRouterStop := strings.Index(src, "router.Stop()")
		if idxSrvRun < 0 || idxRouterStop < 0 {
			t.Fatalf("srv.Run / router.Stop missing — boot sequence broken")
		}
		if idxRouterStop < idxSrvRun {
			t.Errorf("router.Stop() appears BEFORE srv.Run(ctx) — shutdown order broken")
		}
		// defer bus.Shutdown() must appear before NewRouter so its
		// deferred call fires after router.Stop().
		idxDefer := strings.Index(src, "defer bus.Shutdown()")
		idxNewRouter := strings.Index(src, "alertrouter.NewRouter")
		if idxDefer < 0 || idxNewRouter < 0 {
			t.Fatalf("defer bus.Shutdown() / alertrouter.NewRouter missing")
		}
		if idxDefer > idxNewRouter {
			t.Errorf("defer bus.Shutdown() appears AFTER alertrouter.NewRouter — deferred shutdown would fire BEFORE router.Stop, violating reverse order")
		}
	})
}

// @ac AC-04
// AC-04: alertrouter.Start (router.Start(ctx)) precedes the goroutine
// that spawns liveSvc.Run.
func TestCmdServe_RouterStartBeforeLivenessRun(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-04", func(t *testing.T) {
		src := mainGoSource(t)
		idxRouterStart := strings.Index(src, "router.Start(ctx)")
		idxGoLive := strings.Index(src, "go liveSvc.Run(ctx)")
		if idxRouterStart < 0 || idxGoLive < 0 {
			t.Fatalf("router.Start / go liveSvc.Run missing")
		}
		if idxRouterStart > idxGoLive {
			t.Errorf("router.Start(ctx) appears AFTER go liveSvc.Run — bus could see a publish before any subscriber exists (C-09 violation)")
		}
	})
}

// @ac AC-05
// AC-05: no Slice B package calls audit.Emit directly. Each takes its
// EmitFunc via NewX constructor injection.
func TestSliceBPackages_DoNotImportAuditEmit(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-05", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		appDir := filepath.Join(filepath.Dir(file), "..", "..")
		sliceBDirs := []string{
			"internal/scheduler",
			"internal/kensa",
			"internal/transactionlog",
			"internal/liveness",
			"internal/alertrouter",
			"internal/eventbus",
			"internal/fleetrollup",
			"internal/drift",
		}

		// Pattern: audit.Emit(ctx, ...) — direct package-global call.
		// Annotation-only allowance: any line containing //nolint:audit
		// is exempt. (No package uses that today.)
		directCall := regexp.MustCompile(`\baudit\.Emit\(`)

		fset := token.NewFileSet()
		for _, d := range sliceBDirs {
			full := filepath.Join(appDir, d)
			entries, err := os.ReadDir(full)
			if err != nil {
				t.Logf("skip %s (not present): %v", d, err)
				continue
			}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
					continue
				}
				if strings.HasSuffix(e.Name(), "_test.go") {
					continue
				}
				path := filepath.Join(full, e.Name())
				// Parse to ensure file is valid Go (lints + helps avoid
				// false positives in string literals — though regex above
				// is intentionally narrow).
				if _, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly); err != nil {
					t.Errorf("parse %s: %v", path, err)
					continue
				}
				b, err := os.ReadFile(path)
				if err != nil {
					t.Errorf("read %s: %v", path, err)
					continue
				}
				if directCall.MatchString(string(b)) {
					t.Errorf("%s contains a direct audit.Emit(...) call — Slice B packages MUST receive audit.Emit via NewX constructor injection (system-daemon-orchestration AC-05)", path)
				}
			}
		}
	})
}

// @ac AC-06
// AC-06: cmdServe registers the stdout channel with no Tags (wildcard).
func TestCmdServe_RegistersStdoutWildcardChannel(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-06", func(t *testing.T) {
		src := mainGoSource(t)
		// Look for the canonical registration block.
		if !strings.Contains(src, "stdoutchan.New(") {
			t.Error("main.go does not call stdoutchan.New — stdout alert channel not constructed")
		}
		// Channel registered via router.Register with a
		// ChannelRegistration whose Tags field is omitted (nil) or
		// explicit empty map. Regex catches both forms; rejects an
		// explicit non-nil filter that would prevent wildcard match.
		registerRe := regexp.MustCompile(`router\.Register\(alertrouter\.ChannelRegistration\{[^}]*Channel:\s*stdoutchan\.New\([^)]*\)[^}]*\}\)`)
		m := registerRe.FindString(src)
		if m == "" {
			t.Fatal("main.go does not register the stdoutchan via router.Register with a ChannelRegistration{Channel: stdoutchan.New(...)}")
		}
		// Inside the matched block, if a Tags: field is present its
		// value must be nil or an empty map.
		if strings.Contains(m, "Tags:") {
			// Accept Tags: nil or Tags: map[string]string{}.
			tagsOK := strings.Contains(m, "Tags: nil") ||
				strings.Contains(m, "Tags: map[string]string{}") ||
				strings.Contains(m, "Tags:map[string]string{}")
			if !tagsOK {
				t.Errorf("stdout channel registered with a non-wildcard Tags filter; got %q", m)
			}
		}
	})
}

// @ac AC-08
// AC-08: discovery service is constructed with the lookup +
// credential wiring and threaded into the HTTP server via
// server.WithDiscovery. Without this, POST /hosts/{id}/discovery:run
// returns 503 server.unavailable.
func TestCmdServe_DiscoveryServiceWired(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-08", func(t *testing.T) {
		src := mainGoSource(t)
		patterns := []string{
			"discovery.NewService(pool, audit.Emit, bus)",
			"WithHostLookup(discovery.PoolHostLookup{Pool: pool})",
			"WithCredentialService(credSvc)",
			"WithDiscovery(discoSvc)",
		}
		for _, p := range patterns {
			if !strings.Contains(src, p) {
				t.Errorf("main.go missing required pattern for AC-08: %q", p)
			}
		}
	})
}

// @ac AC-09
// AC-09: collector + scheduler are wired and the scheduler runs in
// its own goroutine. WithSSHTransport is required — without it
// collector.RunCycle returns "ssh transport not wired" silently and
// the scheduler does nothing.
func TestCmdServe_IntelligenceSchedulerWired(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-09", func(t *testing.T) {
		src := mainGoSource(t)
		patterns := []string{
			"collector.NewService(pool, audit.Emit, bus)",
			"WithSSHTransport(",
			"scheduler.NewService(pool,",
			"WithConfigLoader(cfgStore.LoadIntelligence)",
		}
		for _, p := range patterns {
			if !strings.Contains(src, p) {
				t.Errorf("main.go missing required pattern for AC-09: %q", p)
			}
		}
		runRe := regexp.MustCompile(`go\s+func\(\)\s*\{\s*_\s*=\s*intelSched\.Run\(ctx\)\s*\}\(\)`)
		if !runRe.MatchString(src) {
			t.Error("main.go does not start intelSched.Run in a goroutine")
		}
	})
}

// @ac AC-10
// AC-10: the boot path logs a WARN when MaintenanceGlobal=true at
// startup. Without this, a paused scheduler is silent and operators
// chase the symptom for an hour.
func TestCmdServe_MaintenancePauseWarnLog(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-10", func(t *testing.T) {
		src := mainGoSource(t)
		if !strings.Contains(src, "cfgStore.LoadIntelligence(bootCtx)") {
			t.Error("main.go does not call cfgStore.LoadIntelligence at boot for the maintenance check")
		}
		if !strings.Contains(src, "cfg.MaintenanceGlobal") {
			t.Error("main.go does not check cfg.MaintenanceGlobal at boot")
		}
		warnRe := regexp.MustCompile(`slog\.WarnContext\(bootCtx,\s*"intelligence scheduler paused at startup"`)
		if !warnRe.MatchString(src) {
			t.Error(`main.go missing slog.WarnContext(bootCtx, "intelligence scheduler paused at startup", ...)`)
		}
	})
}
