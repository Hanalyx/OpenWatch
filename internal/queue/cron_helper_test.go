package queue

import (
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/cron"
)

// schedulerStartCronTest fires the supplied tick on a fast schedule,
// waits for two ticks, and asserts both produced cron- correlation IDs.
// Kept separate to keep queue_test.go focused on assertions.
func schedulerStartCronTest(t *testing.T, tick cron.TickFunc, seen chan string) {
	t.Helper()
	s := cron.New(15*time.Millisecond, tick)
	s.Start(t.Context())
	t.Cleanup(s.Stop)

	got1 := <-seen
	got2 := <-seen
	re := cronCorrelationRegex()
	if !re.MatchString(got1) {
		t.Errorf("tick 1 correlation_id = %q, want cron-<16 hex>", got1)
	}
	if !re.MatchString(got2) {
		t.Errorf("tick 2 correlation_id = %q, want cron-<16 hex>", got2)
	}
	if got1 == got2 {
		t.Errorf("two ticks share correlation_id %q; want distinct per tick", got1)
	}
}
