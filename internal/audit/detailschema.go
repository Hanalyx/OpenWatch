package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
)

// Detail-schema enforcement.
//
// audit/events.yaml lets an event declare a detail_schema describing the keys
// its detail map carries. Eighty events declare one. Until this file existed,
// NOTHING read any of them: scripts/gen-audit-events.go parsed the block into a
// struct field and emitted nothing from it, so an emitter could send any keys,
// omit every declared key, or rename them, and no gate noticed.
//
// That is worse than an undocumented contract, because the declaration reads as
// enforcement. It sits in a generated-code pipeline, in a file whose other
// fields all produce output, written as a JSON Schema fragment. A reader
// reasonably concludes something validates it. See bugs/OW-018.
//
// What this enforces, and what it does not:
//
//   - It checks that a detail map's keys are a SUBSET of the declared set. An
//     undeclared key is a violation.
//   - It does NOT require every declared key to be present. Many events carry a
//     key only in some outcomes (a reason on failure, a count when non-zero),
//     and demanding all of them would push emitters to send nulls, which is
//     worse for the reader than an absent key.
//   - It checks key names only, not types or enums. Emit sees a marshalled map,
//     and a check that half-enforces a schema is worse than one that enforces
//     the key set honestly.
//   - An event declaring no schema is not checked. Absent and empty are the
//     same thing here: nothing to check against.
//
// Coverage is what actually runs. This catches a violation on any emitted
// event, including the thirteen call sites that build their detail map
// dynamically and which no static analysis can reach. It does not prove that
// an unexercised path conforms.

// detailViolations counts schema violations seen since process start. Exported
// through DetailViolations so a test can assert a path emitted cleanly.
var detailViolations atomic.Int64

// DetailViolations returns the number of audit events emitted with a detail key
// the event's declared schema does not list.
//
// A test that exercises an emitting path can assert this stays at zero across
// the path. It is a counter rather than a hard failure at the emit site on
// purpose: an audit event carrying an unexpected key is still worth recording,
// and dropping it would lose the very evidence an operator needs. The contract
// is enforced by the count being asserted, not by the record being discarded.
func DetailViolations() int64 { return detailViolations.Load() }

// checkDetailSchema compares an event's detail keys against the declared set
// for its code. It logs and counts a violation; it never alters the event.
func checkDetailSchema(ctx context.Context, code Code, detail json.RawMessage) {
	meta, ok := Metadata[code]
	if !ok || len(meta.DetailKeys) == 0 || len(detail) == 0 {
		return
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(detail, &got); err != nil {
		// A detail that is not a JSON object is out of scope here. Redaction
		// and the writer deal with shape; this function only knows key names.
		return
	}

	allowed := make(map[string]struct{}, len(meta.DetailKeys))
	for _, k := range meta.DetailKeys {
		allowed[k] = struct{}{}
	}

	var undeclared []string
	for k := range got {
		if _, ok := allowed[k]; !ok {
			undeclared = append(undeclared, k)
		}
	}
	if len(undeclared) == 0 {
		return
	}
	sort.Strings(undeclared)

	detailViolations.Add(1)
	slog.WarnContext(ctx, "audit detail carries keys its declared schema does not list",
		slog.String("action", string(code)),
		slog.String("undeclared", strings.Join(undeclared, ",")),
		slog.String("declared", strings.Join(meta.DetailKeys, ",")),
		slog.String("fix", "add the key to detail_schema in audit/events.yaml, or stop sending it"),
	)
}
