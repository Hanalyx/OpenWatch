// Package specfixture loads acceptance-criteria fixtures out of a Specter spec
// so tests are driven by the spec rather than by numbers copied beside it.
//
// Specter counts a criterion covered when a test carries its annotation, not
// when the test asserts what the criterion says. Nothing in the toolchain checks
// that a test consumed the criterion's inputs or expected_output, so an
// annotation on a test that hardcodes its values reports coverage it does not
// have. This package makes the YAML the input and fails when a supplied field
// goes unread.
//
// It lives in a non-test file because three packages need it. It has no
// production callers and imports nothing but the standard library and yaml.
package specfixture

import (
	"fmt"
	"math"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// Criterion is one acceptance criterion's executable content.
type Criterion struct {
	ID             string         `yaml:"id"`
	Description    string         `yaml:"description"`
	Priority       string         `yaml:"priority"`
	Inputs         map[string]any `yaml:"inputs"`
	ExpectedOutput map[string]any `yaml:"expected_output"`
}

type specDoc struct {
	Spec struct {
		ID                 string      `yaml:"id"`
		Version            string      `yaml:"version"`
		AcceptanceCriteria []Criterion `yaml:"acceptance_criteria"`
	} `yaml:"spec"`
}

// TB is the subset of testing.TB this package needs, so it can be used from any
// test package without importing testing into a production build.
type TB interface {
	Helper()
	Fatalf(string, ...any)
	Errorf(string, ...any)
}

// Load reads a spec file and indexes its criteria by id, failing on a duplicate.
//
// A duplicate id is fatal rather than last-wins: two criteria sharing one id let
// a single annotation report coverage for unrelated behavior, which is how
// OW-023's new criteria silently collided with the drift event-bus criteria.
func Load(t TB, path, wantSpecID string) map[string]Criterion {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("specfixture: read %s: %v", path, err)
	}
	var doc specDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("specfixture: parse %s: %v", path, err)
	}
	if doc.Spec.ID != wantSpecID {
		t.Fatalf("specfixture: %s declares id %q, want %q", path, doc.Spec.ID, wantSpecID)
	}
	out := make(map[string]Criterion, len(doc.Spec.AcceptanceCriteria))
	for _, ac := range doc.Spec.AcceptanceCriteria {
		if _, dup := out[ac.ID]; dup {
			t.Fatalf("specfixture: %s declares %s twice; one annotation would cover both", path, ac.ID)
		}
		out[ac.ID] = ac
	}
	return out
}

// Get fetches one criterion and fails when it is missing or carries no fixture.
func Get(t TB, all map[string]Criterion, id string) Criterion {
	t.Helper()
	ac, ok := all[id]
	if !ok {
		t.Fatalf("specfixture: %s not found", id)
	}
	if len(ac.Inputs) == 0 {
		t.Fatalf("specfixture: %s has no inputs; the fixture belongs in the spec", id)
	}
	if len(ac.ExpectedOutput) == 0 {
		t.Fatalf("specfixture: %s has no expected_output", id)
	}
	return ac
}

// Fields wraps one map and records which keys a test read.
type Fields struct {
	t    TB
	id   string
	side string
	m    map[string]any
	seen map[string]bool
}

// InputsOf and ExpectedOf wrap the two halves of a criterion.
func InputsOf(t TB, ac Criterion) *Fields {
	return &Fields{t: t, id: ac.ID, side: "inputs", m: ac.Inputs, seen: map[string]bool{}}
}

func ExpectedOf(t TB, ac Criterion) *Fields {
	return &Fields{t: t, id: ac.ID, side: "expected_output", m: ac.ExpectedOutput, seen: map[string]bool{}}
}

func (f *Fields) get(k string) any {
	f.t.Helper()
	v, ok := f.m[k]
	if !ok {
		f.t.Fatalf("%s: %s has no %q", f.id, f.side, k)
	}
	f.seen[k] = true
	return v
}

// Num reads a numeric field.
func (f *Fields) Num(k string) float64 {
	f.t.Helper()
	switch n := f.get(k).(type) {
	case float64:
		return n
	case int:
		return float64(n)
	default:
		f.t.Fatalf("%s: %s.%s = %v (%T), want a number", f.id, f.side, k, n, n)
		return 0
	}
}

// Int reads an integer field, rejecting a fractional value.
//
// Truncating silently would let a spec say 2.5 hosts and a test assert 2, so the
// fixture and the assertion would disagree with nothing failing.
func (f *Fields) Int(k string) int {
	f.t.Helper()
	n := f.Num(k)
	if n != math.Trunc(n) {
		f.t.Fatalf("%s: %s.%s = %v, want a whole number", f.id, f.side, k, n)
	}
	return int(n)
}

// Str reads a string field.
func (f *Fields) Str(k string) string {
	f.t.Helper()
	v, ok := f.get(k).(string)
	if !ok {
		f.t.Fatalf("%s: %s.%s is not a string", f.id, f.side, k)
	}
	return v
}

// Bool reads a boolean field.
func (f *Fields) Bool(k string) bool {
	f.t.Helper()
	v, ok := f.get(k).(bool)
	if !ok {
		f.t.Fatalf("%s: %s.%s is not a bool", f.id, f.side, k)
	}
	return v
}

// IsNull asserts an explicit null. A missing key and a null are different
// claims, so get fails on the former.
func (f *Fields) IsNull(k string) {
	f.t.Helper()
	if v := f.get(k); v != nil {
		f.t.Fatalf("%s: %s.%s = %v, want null", f.id, f.side, k, v)
	}
}

// List reads a list field.
func (f *Fields) List(k string) []any {
	f.t.Helper()
	v, ok := f.get(k).([]any)
	if !ok {
		f.t.Fatalf("%s: %s.%s is not a list", f.id, f.side, k)
	}
	return v
}

// EmptyList requires an actual empty list. null is rejected: accepting it would
// let `violations: []` become `violations: null` with the test still passing.
func (f *Fields) EmptyList(k string) {
	f.t.Helper()
	v := f.get(k)
	l, ok := v.([]any)
	if !ok {
		f.t.Fatalf("%s: %s.%s = %v (%T), want an empty list and not null", f.id, f.side, k, v, v)
	}
	if len(l) != 0 {
		f.t.Fatalf("%s: %s.%s = %v, want an empty list", f.id, f.side, k, v)
	}
}

// Map reads a nested mapping and returns it wrapped, so nested fields are
// tracked too.
func (f *Fields) Map(k string) *Fields {
	f.t.Helper()
	v, ok := f.get(k).(map[string]any)
	if !ok {
		f.t.Fatalf("%s: %s.%s is not a mapping", f.id, f.side, k)
	}
	return &Fields{t: f.t, id: f.id, side: f.side + "." + k, m: v, seen: map[string]bool{}}
}

// IsNullable reports whether a present key holds null, WITHOUT marking it read.
//
// For a field that is legitimately either a value or null. The caller must still
// consume it: either IsNull to assert the null, or a typed accessor for the
// value. Peeking does not count as asserting.
func (f *Fields) IsNullable(k string) bool {
	f.t.Helper()
	v, ok := f.m[k]
	if !ok {
		f.t.Fatalf("%s: %s has no %q", f.id, f.side, k)
	}
	return v == nil
}

// StrList reads a list expectation whose entries are all strings.
//
// It exists so a caller does not have to type-assert each element and, more
// importantly, so a list holding a non-string fails loudly here rather than
// being silently skipped by a caller's type switch.
func (f *Fields) StrList(k string) []string {
	f.t.Helper()
	raw := f.List(k)
	out := make([]string, 0, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		if !ok {
			f.t.Fatalf("%s: %s.%s[%d] is %T, want a string", f.id, f.side, k, i, v)
		}
		out = append(out, s)
	}
	return out
}

// MapList reads a list of mappings and wraps each, so nested fixture entries are
// consumption-tracked individually.
func (f *Fields) MapList(k string) []*Fields {
	f.t.Helper()
	raw := f.List(k)
	out := make([]*Fields, 0, len(raw))
	for i, e := range raw {
		m, ok := e.(map[string]any)
		if !ok {
			f.t.Fatalf("%s: %s.%s[%d] is not a mapping", f.id, f.side, k, i)
		}
		out = append(out, &Fields{
			t: f.t, id: f.id, side: fmt.Sprintf("%s.%s[%d]", f.side, k, i),
			m: m, seen: map[string]bool{},
		})
	}
	return out
}

// Has reports whether a key exists, without marking it read.
func (f *Fields) Has(k string) bool { _, ok := f.m[k]; return ok }

// Raw returns the underlying mapping and marks every key read. For a nested
// fixture whose shape a caller interprets itself; prefer the typed accessors
// where the shape is fixed.
func (f *Fields) Raw() map[string]any {
	for k := range f.m {
		f.seen[k] = true
	}
	return f.m
}

// AllConsumed fails when the criterion supplies something no assertion read.
//
// Call it only from a test that claims the criterion with an @ac annotation.
func (f *Fields) AllConsumed() {
	f.t.Helper()
	var missed []string
	for k := range f.m {
		if !f.seen[k] {
			missed = append(missed, k)
		}
	}
	sort.Strings(missed)
	if len(missed) > 0 {
		f.t.Errorf("%s: %s keys never asserted: %v. Assert them, or drop the @ac annotation until a test covers the whole criterion.",
			f.id, f.side, missed)
	}
}

// Path builds a repository-relative spec path from a package directory depth.
func Path(depth int, rel string) string {
	up := ""
	for i := 0; i < depth; i++ {
		up += "../"
	}
	return fmt.Sprintf("%s%s", up, rel)
}
