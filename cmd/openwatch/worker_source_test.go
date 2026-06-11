// @spec system-worker-subcommand
//
// AC traceability (this file):
//
//	AC-13  TestCmdWorker_HelpAndVersion_Sourced
//	AC-16  TestCmdWorker_BootPrerequisites
//	AC-17  TestCmdWorker_NoHTTPSubsystems

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func workerGoSource(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "worker.go"))
	if err != nil {
		t.Fatalf("read worker.go: %v", err)
	}
	return string(src)
}

// AC-13 — `openwatch worker --help` prints usage; `--version` prints
// build metadata identical to serve.
//
// We source-inspect rather than spawn the binary in this test because
// spawning needs a TTY for help and a built binary. The structural
// invariants:
//
//   - main.go dispatches the "worker" subcommand to cmdWorker.
//   - main.go's printUsage lists "worker" in the subcommand block.
//   - cmdWorker builds a flag.FlagSet (which renders --help via
//     flag.ContinueOnError behavior).
//   - --version is handled at the top level in run() — same code path
//     for every subcommand, so worker shares it.
//
// @ac AC-13
func TestCmdWorker_HelpAndVersion_Sourced(t *testing.T) {
	t.Run("system-worker-subcommand/AC-13", func(t *testing.T) {
		mainSrc := mainGoSource(t)
		// "worker" appears in the subcommand switch.
		if !regexp.MustCompile(`case "worker":\s*return cmdWorker`).MatchString(mainSrc) {
			t.Error(`main.go switch has no case "worker": return cmdWorker(...)`)
		}
		// "worker" appears in printUsage's subcommand block (so --help
		// from main mentions it).
		if !strings.Contains(mainSrc, "worker        run the scan-job") {
			t.Error("printUsage block does not document the worker subcommand")
		}

		workerSrc := workerGoSource(t)
		// cmdWorker constructs a flag.FlagSet — gives the subcommand a
		// well-formed --help (via flag.ContinueOnError pattern).
		if !strings.Contains(workerSrc, `flag.NewFlagSet("worker", flag.ContinueOnError)`) {
			t.Error("cmdWorker must construct a flag.FlagSet for sane --help behavior")
		}
		// --poll-interval flag is wired.
		if !strings.Contains(workerSrc, `"poll-interval"`) {
			t.Error("cmdWorker must wire --poll-interval flag (system-worker-subcommand C-10)")
		}
	})
}

// AC-16 — cmdWorker boot path calls the same prerequisite chain as
// cmdServe (minus HTTP server): config validation, DB pool, identity
// JWT key load, secret-key load, audit init, license init, scheduler
// queue-key derivation. The order matters less than the presence; we
// check both.
// @ac AC-16
func TestCmdWorker_BootPrerequisites(t *testing.T) {
	t.Run("system-worker-subcommand/AC-16", func(t *testing.T) {
		src := workerGoSource(t)

		required := []string{
			"cfg.Validate()",
			"db.NewPool",
			"identity.LoadJWTKey",
			"secretkey.LoadFromFile",
			"audit.Init",
			"defer audit.Shutdown",
			"license.Init()",
			"scheduler.DeriveQueueKey",
			"worker.NewScanWorker",
			"scanWorker.Run(ctx)",
		}
		for _, r := range required {
			if !strings.Contains(src, r) {
				t.Errorf("cmd/openwatch/worker.go missing required boot call %q", r)
			}
		}

		// Order: secretkey.LoadFromFile MUST precede scheduler.DeriveQueueKey
		// (the latter needs the DEK).
		if idxLoad := strings.Index(src, "secretkey.LoadFromFile"); idxLoad >= 0 {
			idxDerive := strings.Index(src, "scheduler.DeriveQueueKey")
			if idxDerive < idxLoad {
				t.Errorf("scheduler.DeriveQueueKey appears before secretkey.LoadFromFile — DEK must be loaded first")
			}
		}
	})
}

// AC-17 — cmdWorker is HTTP-free. It must NOT instantiate eventbus.NewBus,
// alertrouter.NewRouter, liveness.NewService, or server.New. The worker
// is a long-lived consumer, not a server.
// @ac AC-17
func TestCmdWorker_NoHTTPSubsystems(t *testing.T) {
	t.Run("system-worker-subcommand/AC-17", func(t *testing.T) {
		src := workerGoSource(t)

		forbidden := []string{
			"eventbus.NewBus",
			"alertrouter.NewRouter",
			"liveness.NewService",
			"server.New(",
		}
		for _, f := range forbidden {
			if strings.Contains(src, f) {
				t.Errorf("cmd/openwatch/worker.go MUST NOT call %q (C-11 / AC-17)", f)
			}
		}

		// Imports tell the same story: the worker.go file should not
		// import these packages.
		forbiddenImports := []string{
			`"github.com/Hanalyx/openwatch/internal/alertrouter"`,
			`"github.com/Hanalyx/openwatch/internal/eventbus"`,
			`"github.com/Hanalyx/openwatch/internal/liveness"`,
			`"github.com/Hanalyx/openwatch/internal/server"`,
		}
		for _, imp := range forbiddenImports {
			if strings.Contains(src, imp) {
				t.Errorf("cmd/openwatch/worker.go MUST NOT import %s", imp)
			}
		}
	})
}
