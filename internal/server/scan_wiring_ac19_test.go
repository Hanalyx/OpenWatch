// @spec system-worker-subcommand
//
// AC traceability (this file):
//
//	AC-19  TestServe_ScanWorkerIsActuallyRegistered

package server

import (
	"testing"

	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/worker"
)

// AC-19, behavioral half. The packaged unit runs `openwatch serve` and
// nothing else, so serve is what scans on a default install. That was
// asserted by grepping main.go for `WithScanWorker(`, which a
// registration wrapped in an impossible branch satisfies exactly as well
// as a real one.
//
// This builds a Server the way serve builds one, registers a scan worker
// through the same method, and asks the in-process job runner whether it
// is carrying a scan processor. `if s.wkr != nil && false` fails here.
//
// The packaging and worker-subcommand halves of AC-19 stay in
// cmd/openwatch/worker_source_test.go, where the facts are genuinely
// about a shipped file and a subcommand's source.
// @ac AC-19
func TestServe_ScanWorkerIsActuallyRegistered(t *testing.T) {
	t.Run("system-worker-subcommand/AC-19", func(t *testing.T) {
		pool := dbtest.Pool(t)
		cfg := config.Defaults()
		s := New(cfg, pool)

		if s.ScanWorkerRegistered() {
			t.Fatal("a freshly built server already reports a scan processor; " +
				"the check cannot distinguish registered from not")
		}

		sw := worker.NewScanWorker(worker.Config{})
		s.WithScanWorker(sw)

		if !s.ScanWorkerRegistered() {
			t.Error("WithScanWorker did not put a scan processor on the in-process job " +
				"runner. serve would claim scan jobs from the queue and dead-end them, " +
				"and on a packaged install nothing else is running to pick them up.")
		}
	})
}
