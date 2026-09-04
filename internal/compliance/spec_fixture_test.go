package compliance

// Fixture loader for the spec's structured acceptance-criteria fields.
//
// The tests in this package do not restate the numbers from
// specs/system/compliance-scoring.spec.yaml. They read them.
//
// That is deliberate and it is the only thing that makes `inputs` and
// `expected_output` load-bearing. Specter 0.14.0 validates that those fields
// parse; it does not check that any test consumes them, and no repository guard
// can prove an expected value is correct. A criterion whose numbers live only
// in YAML nothing reads is a declared surface carrying nothing, which is the
// defect class this whole spec exists to prevent. So the YAML is the input to
// the test, and a criterion edited without a corresponding behavior change
// fails here.

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// specPath is relative to this package directory.
const specPath = "../../specs/system/compliance-scoring.spec.yaml"

type acceptanceCriterion struct {
	ID             string         `yaml:"id"`
	Description    string         `yaml:"description"`
	Priority       string         `yaml:"priority"`
	Inputs         map[string]any `yaml:"inputs"`
	ExpectedOutput map[string]any `yaml:"expected_output"`
}

type specDoc struct {
	Spec struct {
		ID                 string                `yaml:"id"`
		Version            string                `yaml:"version"`
		AcceptanceCriteria []acceptanceCriterion `yaml:"acceptance_criteria"`
	} `yaml:"spec"`
}

// loadCriteria reads the spec once and indexes its criteria by id.
func loadCriteria(t *testing.T) map[string]acceptanceCriterion {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(specPath))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc specDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	if doc.Spec.ID != "system-compliance-scoring" {
		t.Fatalf("spec id = %q, want system-compliance-scoring", doc.Spec.ID)
	}
	out := make(map[string]acceptanceCriterion, len(doc.Spec.AcceptanceCriteria))
	for _, ac := range doc.Spec.AcceptanceCriteria {
		out[ac.ID] = ac
	}
	return out
}

// criterion fetches one AC and fails loudly when it is missing or carries no
// fixture. A silently skipped criterion would be worse than a failing one.
func criterion(t *testing.T, all map[string]acceptanceCriterion, id string) acceptanceCriterion {
	t.Helper()
	ac, ok := all[id]
	if !ok {
		t.Fatalf("%s not found in %s", id, specPath)
	}
	if len(ac.Inputs) == 0 {
		t.Fatalf("%s has no inputs; the fixture must live in the spec, not in this test", id)
	}
	if len(ac.ExpectedOutput) == 0 {
		t.Fatalf("%s has no expected_output", id)
	}
	return ac
}

// countsFrom builds Counts from a spec `counts` mapping.
func countsFrom(t *testing.T, m map[string]any) Counts {
	t.Helper()
	raw, ok := m["counts"]
	if !ok {
		t.Fatalf("inputs carry no counts mapping")
	}
	c, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("counts is %T, want a mapping", raw)
	}
	return Counts{
		Pass:    intField(t, c, "pass"),
		Fail:    intField(t, c, "fail"),
		Skipped: intField(t, c, "skipped"),
		Error:   intField(t, c, "error"),
	}
}

func intField(t *testing.T, m map[string]any, k string) int {
	t.Helper()
	v, ok := m[k]
	if !ok {
		return 0
	}
	n, ok := v.(int)
	if !ok {
		t.Fatalf("%s = %v (%T), want an int", k, v, v)
	}
	return n
}

// expectations wraps one criterion's expected_output and records which keys a
// test actually consumed.
//
// This exists because Specter counts a criterion as covered when a test carries
// its annotation, not when the test asserts what the criterion says. Annotating
// a test that checks two of six expected values overstates coverage in exactly
// the way this spec exists to prevent: a declared surface reporting a fact it
// did not measure. allConsumed makes the overstatement fail instead.
type expectations struct {
	t    *testing.T
	id   string
	m    map[string]any
	seen map[string]bool
}

func expectationsOf(t *testing.T, ac acceptanceCriterion) *expectations {
	t.Helper()
	return &expectations{t: t, id: ac.ID, m: ac.ExpectedOutput, seen: map[string]bool{}}
}

func (e *expectations) get(k string) any {
	e.t.Helper()
	v, ok := e.m[k]
	if !ok {
		e.t.Fatalf("%s: expected_output has no %q", e.id, k)
	}
	e.seen[k] = true
	return v
}

// num reads a numeric expectation.
func (e *expectations) num(k string) float64 {
	e.t.Helper()
	switch n := e.get(k).(type) {
	case float64:
		return n
	case int:
		return float64(n)
	default:
		e.t.Fatalf("%s: %s = %v (%T), want a number", e.id, k, n, n)
		return 0
	}
}

// str reads a string expectation.
func (e *expectations) str(k string) string {
	e.t.Helper()
	v, ok := e.get(k).(string)
	if !ok {
		e.t.Fatalf("%s: %s is not a string", e.id, k)
	}
	return v
}

// boolean reads a bool expectation.
func (e *expectations) boolean(k string) bool {
	e.t.Helper()
	v, ok := e.get(k).(bool)
	if !ok {
		e.t.Fatalf("%s: %s is not a bool", e.id, k)
	}
	return v
}

// isNull asserts the spec expects an explicit null. A missing key and a null
// are different claims, so get fails on the former.
func (e *expectations) isNull(k string) {
	e.t.Helper()
	if v := e.get(k); v != nil {
		e.t.Fatalf("%s: %s = %v, want null", e.id, k, v)
	}
}

// list reads a list expectation.
func (e *expectations) list(k string) []any {
	e.t.Helper()
	v, ok := e.get(k).([]any)
	if !ok {
		e.t.Fatalf("%s: %s is not a list", e.id, k)
	}
	return v
}

// emptyList asserts a key holds an actual empty list.
//
// null is rejected rather than treated as empty. Accepting it would let
// `violations: []` be edited to `violations: null` with the test still passing,
// which is the same "absent reads as a real answer" defect the spec forbids of
// the product.
func (e *expectations) emptyList(k string) {
	e.t.Helper()
	v := e.get(k)
	l, ok := v.([]any)
	if !ok {
		e.t.Fatalf("%s: %s = %v (%T), want an empty list and not null", e.id, k, v, v)
	}
	if len(l) != 0 {
		e.t.Fatalf("%s: %s = %v, want an empty list", e.id, k, v)
	}
}

// allConsumed fails when the criterion expects something no assertion read.
//
// Call it only from a test that claims the criterion with an @ac annotation. A
// partial unit test must not call it and must not carry the annotation.
func (e *expectations) allConsumed() {
	e.t.Helper()
	var missed []string
	for k := range e.m {
		if !e.seen[k] {
			missed = append(missed, k)
		}
	}
	sort.Strings(missed)
	if len(missed) > 0 {
		e.t.Errorf("%s: expected_output keys never asserted: %v. "+
			"Either assert them or drop the @ac annotation until a test covers the whole criterion.", e.id, missed)
	}
}

// fixtureInputs wraps one criterion's inputs and records which keys a test read.
//
// The output side had this from the start and the input side did not, so a test
// could load a criterion, hardcode the package path and fixture name, and still
// report the criterion covered. Changing source_path in the spec would not have
// failed anything. Inputs must drive the test or they are prose in the wrong
// field.
type fixtureInputs struct {
	t    *testing.T
	id   string
	m    map[string]any
	seen map[string]bool
}

func inputsOf(t *testing.T, ac acceptanceCriterion) *fixtureInputs {
	t.Helper()
	return &fixtureInputs{t: t, id: ac.ID, m: ac.Inputs, seen: map[string]bool{}}
}

func (f *fixtureInputs) strList(k string) []string {
	f.t.Helper()
	v, ok := f.m[k]
	if !ok {
		f.t.Fatalf("%s: inputs has no %q", f.id, k)
	}
	f.seen[k] = true
	raw, ok := v.([]any)
	if !ok {
		f.t.Fatalf("%s: inputs.%s is %T, want a list", f.id, k, v)
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		sv, ok := e.(string)
		if !ok {
			f.t.Fatalf("%s: inputs.%s holds %T, want strings", f.id, k, e)
		}
		out = append(out, sv)
	}
	return out
}

func (f *fixtureInputs) str(k string) string {
	f.t.Helper()
	v, ok := f.m[k]
	if !ok {
		f.t.Fatalf("%s: inputs has no %q", f.id, k)
	}
	f.seen[k] = true
	sv, ok := v.(string)
	if !ok {
		f.t.Fatalf("%s: inputs.%s is %T, want a string", f.id, k, v)
	}
	return sv
}

// allConsumed fails when the criterion supplies an input no assertion used.
func (f *fixtureInputs) allConsumed() {
	f.t.Helper()
	var missed []string
	for k := range f.m {
		if !f.seen[k] {
			missed = append(missed, k)
		}
	}
	sort.Strings(missed)
	if len(missed) > 0 {
		f.t.Errorf("%s: inputs never used: %v. Drive the test from them or move the prose into description.", f.id, missed)
	}
}
