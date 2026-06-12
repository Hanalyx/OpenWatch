package scheduler

import (
	"context"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// emitCall is a captured audit emission used by the fake emitter.
type emitCall struct {
	Code  audit.Code
	Event audit.Event
}

// fakeEmitter returns an EmitFunc that appends every call to *calls.
// Closure pattern keeps the test bodies short.
func fakeEmitter(calls *[]emitCall) EmitFunc {
	return func(ctx context.Context, code audit.Code, ev audit.Event) {
		*calls = append(*calls, emitCall{Code: code, Event: ev})
	}
}
