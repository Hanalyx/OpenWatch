// Tests for the fixture loader itself.
//
// This package is the thing that decides whether a criterion is really covered,
// so its own failure modes have to be observed rather than assumed. Every case
// below is a way it could report success while measuring nothing.
package specfixture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recorder captures failures instead of aborting, so a test can assert that the
// loader failed and why.
type recorder struct {
	fatals []string
	errors []string
}

func (r *recorder) Helper()                   {}
func (r *recorder) Fatalf(f string, a ...any) { r.fatals = append(r.fatals, sprintf(f, a...)) }
func (r *recorder) Errorf(f string, a ...any) { r.errors = append(r.errors, sprintf(f, a...)) }
func sprintf(f string, a ...any) string       { return fmt.Sprintf(f, a...) }

func writeSpec(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.spec.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

const oneAC = `
spec:
  id: sys-x
  version: "1.0.0"
  acceptance_criteria:
    - id: AC-01
      inputs: {a: 1, b: two}
      expected_output: {ok: true, list: [], n: 2}
`

// A duplicate id lets one annotation report coverage for unrelated behavior,
// which is how the OW-023 criteria silently collided with the drift event-bus
// criteria. It must be fatal, not last-wins.
func TestLoad_RejectsDuplicateID(t *testing.T) {
	p := writeSpec(t, `
spec:
  id: sys-x
  version: "1.0.0"
  acceptance_criteria:
    - id: AC-01
      inputs: {a: 1}
      expected_output: {ok: true}
    - id: AC-01
      inputs: {a: 2}
      expected_output: {ok: false}
`)
	r := &recorder{}
	Load(r, p, "sys-x")
	if len(r.fatals) == 0 || !strings.Contains(r.fatals[0], "twice") {
		t.Errorf("duplicate id accepted; fatals = %v", r.fatals)
	}
}

// An unread field is the difference between a covered criterion and an
// annotated one.
func TestAllConsumed_ReportsUnreadFields(t *testing.T) {
	all := Load(t, writeSpec(t, oneAC), "sys-x")
	ac := Get(t, all, "AC-01")

	in := InputsOf(t, ac)
	_ = in.Int("a") // b never read
	r := &recorder{}
	(&Fields{t: r, id: ac.ID, side: "inputs", m: ac.Inputs, seen: in.seen}).AllConsumed()
	if len(r.errors) == 0 || !strings.Contains(r.errors[0], "b") {
		t.Errorf("unread input not reported; errors = %v", r.errors)
	}
}

// null is not an empty list. Accepting it would let `violations: []` become
// `violations: null` with the test still passing.
func TestEmptyList_RejectsNull(t *testing.T) {
	p := writeSpec(t, `
spec:
  id: sys-x
  version: "1.0.0"
  acceptance_criteria:
    - id: AC-01
      inputs: {a: 1}
      expected_output: {list: null}
`)
	all := Load(t, p, "sys-x")
	ac := Get(t, all, "AC-01")
	r := &recorder{}
	(&Fields{t: r, id: ac.ID, side: "expected_output", m: ac.ExpectedOutput, seen: map[string]bool{}}).EmptyList("list")
	if len(r.fatals) == 0 || !strings.Contains(r.fatals[0], "not null") {
		t.Errorf("null accepted as an empty list; fatals = %v", r.fatals)
	}
}

// A nested mapping tracks its own consumption, so a fixture cannot hide unread
// fields one level down.
func TestMap_TracksNestedConsumption(t *testing.T) {
	p := writeSpec(t, `
spec:
  id: sys-x
  version: "1.0.0"
  acceptance_criteria:
    - id: AC-01
      inputs: {counts: {pass: 8, fail: 2}}
      expected_output: {ok: true}
`)
	all := Load(t, p, "sys-x")
	ac := Get(t, all, "AC-01")
	in := InputsOf(t, ac)
	nested := in.Map("counts")
	_ = nested.Int("pass") // fail never read
	r := &recorder{}
	(&Fields{t: r, id: ac.ID, side: "inputs.counts", m: nested.m, seen: nested.seen}).AllConsumed()
	if len(r.errors) == 0 || !strings.Contains(r.errors[0], "fail") {
		t.Errorf("unread nested field not reported; errors = %v", r.errors)
	}
}

// Truncating silently would let a spec say 2.5 and a test assert 2, so the
// fixture and the assertion would disagree with nothing failing.
func TestInt_RejectsFractional(t *testing.T) {
	p := writeSpec(t, `
spec:
  id: sys-x
  version: "1.0.0"
  acceptance_criteria:
    - id: AC-01
      inputs: {n: 2.5}
      expected_output: {ok: true}
`)
	all := Load(t, p, "sys-x")
	ac := Get(t, all, "AC-01")
	r := &recorder{}
	(&Fields{t: r, id: ac.ID, side: "inputs", m: ac.Inputs, seen: map[string]bool{}}).Int("n")
	if len(r.fatals) == 0 || !strings.Contains(r.fatals[0], "whole number") {
		t.Errorf("fractional value truncated silently; fatals = %v", r.fatals)
	}
}

// A criterion with no fixture is not usable, and saying so beats a test that
// quietly asserts nothing.
func TestGet_RejectsCriterionWithoutFixture(t *testing.T) {
	p := writeSpec(t, `
spec:
  id: sys-x
  version: "1.0.0"
  acceptance_criteria:
    - id: AC-01
      inputs: {}
      expected_output: {ok: true}
`)
	all := Load(t, p, "sys-x")
	r := &recorder{}
	Get(r, all, "AC-01")
	if len(r.fatals) == 0 || !strings.Contains(r.fatals[0], "no inputs") {
		t.Errorf("criterion without inputs accepted; fatals = %v", r.fatals)
	}
}
