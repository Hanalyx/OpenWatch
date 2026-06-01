// @spec system-intelligence-scheduler
//
// AC traceability (this file):
//
//	AC-13  TestService_RateLimit_BoundsConcurrency
//	AC-14  TestService_Stop_WaitsForInflightCycle

package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// @ac AC-13
// AC-13: RateLimit=2 against 5 queued hosts → at most 2 concurrent
// RunCycles in flight at any moment.
func TestService_RateLimit_BoundsConcurrency(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-13", func(t *testing.T) {
		var active int32
		var maxObserved int32
		var wg sync.WaitGroup
		release := make(chan struct{})

		stub := &stubRunner{
			run: func(_ context.Context, _ uuid.UUID) error {
				cur := atomic.AddInt32(&active, 1)
				for {
					o := atomic.LoadInt32(&maxObserved)
					if cur <= o || atomic.CompareAndSwapInt32(&maxObserved, o, cur) {
						break
					}
				}
				<-release
				atomic.AddInt32(&active, -1)
				return nil
			},
		}

		svc := NewService(nil, stub).WithRateLimit(2)
		hosts := []uuid.UUID{newUUID(), newUUID(), newUUID(), newUUID(), newUUID()}

		for _, h := range hosts {
			wg.Add(1)
			go func(id uuid.UUID) {
				defer wg.Done()
				svc.dispatchHostInPool(context.Background(), id)
			}(h)
		}

		// Give goroutines time to ramp.
		time.Sleep(50 * time.Millisecond)
		got := atomic.LoadInt32(&maxObserved)
		close(release)
		wg.Wait()

		if got > 2 {
			t.Errorf("max concurrent RunCycles = %d, want <= 2 (RateLimit cap)", got)
		}
	})
}

// @ac AC-14
// AC-14: Stop blocks until in-flight RunCycles complete.
func TestService_Stop_WaitsForInflightCycle(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-14", func(t *testing.T) {
		runFinished := make(chan struct{})
		stub := &stubRunner{
			run: func(_ context.Context, _ uuid.UUID) error {
				time.Sleep(80 * time.Millisecond)
				close(runFinished)
				return nil
			},
		}
		svc := NewService(nil, stub).WithRateLimit(1)

		go svc.dispatchHostInPool(context.Background(), newUUID())
		// Let the stub start.
		time.Sleep(20 * time.Millisecond)

		stopReturned := make(chan struct{})
		go func() {
			svc.Stop()
			close(stopReturned)
		}()

		// Stop MUST NOT return before the in-flight cycle finishes.
		select {
		case <-stopReturned:
			t.Fatalf("Stop returned before in-flight RunCycle finished")
		case <-time.After(20 * time.Millisecond):
			// Expected — still in flight.
		}
		<-runFinished
		select {
		case <-stopReturned:
			// Expected — Stop returns now that the cycle's done.
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("Stop did not return within 500ms of in-flight RunCycle completing")
		}
	})
}

// stubRunner is the test-only RunCycleRunner. The single run hook lets
// tests freeze (release-channel pattern) and count entries.
type stubRunner struct {
	run func(ctx context.Context, hostID uuid.UUID) error
}

func (s *stubRunner) RunCycle(ctx context.Context, hostID uuid.UUID) ([]any, error) {
	// scheduler.RunCycleRunner returns (something, error); the
	// scheduler doesn't care about the "something" — it just bumps
	// state on error. We return nil-events here.
	if s.run != nil {
		return nil, s.run(ctx, hostID)
	}
	return nil, nil
}

func newUUID() uuid.UUID {
	id, _ := uuid.NewV7()
	return id
}
