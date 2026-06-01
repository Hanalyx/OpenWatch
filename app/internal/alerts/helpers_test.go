package alerts

import (
	"context"
	"sync"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// auditCounter is the in-test audit emit recorder.
type auditCounter struct {
	mu     sync.Mutex
	counts map[audit.Code]int
}

func newAuditCounter() *auditCounter {
	return &auditCounter{counts: map[audit.Code]int{}}
}

func (a *auditCounter) Emit(_ context.Context, code audit.Code, _ audit.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counts[code]++
}

func (a *auditCounter) CountFor(code string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.counts[audit.Code(code)]
}
