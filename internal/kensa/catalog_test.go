// @spec api-host-compliance
//
// AC traceability (this file):
//
//	AC-03  TestRuleCatalog_UnknownAndNil_FallbackContract
//
// Plus plain unit tests for the Get mapping (no corpus needed —
// catalogs are constructed from in-memory []*api.Rule).

package kensa

import (
	"testing"

	kensaapi "github.com/Hanalyx/kensa/api"
)

func testCatalog() *RuleCatalog {
	return NewRuleCatalogFromRules([]*kensaapi.Rule{
		{
			ID:       "sshd_disable_root_login",
			Title:    "Disable SSH root login",
			Category: "ssh",
			Severity: "high",
		},
		{
			ID:       "kernel_aslr_enabled",
			Title:    "Enable ASLR",
			Category: "kernel",
			Severity: "medium",
		},
		nil,      // nil entries must be skipped, not panic
		{ID: ""}, // empty ids are not indexable
	})
}

// Get returns the full metadata projection for a known id.
func TestRuleCatalog_Get_KnownRule(t *testing.T) {
	c := testCatalog()
	m, ok := c.Get("sshd_disable_root_login")
	if !ok {
		t.Fatal("Get(known id) reported unknown")
	}
	want := RuleMeta{Title: "Disable SSH root login", Category: "ssh", Severity: "high"}
	if m != want {
		t.Errorf("Get = %+v, want %+v", m, want)
	}
	if c.Len() != 2 {
		t.Errorf("Len = %d, want 2 (nil + empty-id entries skipped)", c.Len())
	}
}

// Construction from an empty slice yields a working, empty catalog.
func TestRuleCatalog_Get_EmptyCatalog(t *testing.T) {
	c := NewRuleCatalogFromRules(nil)
	if _, ok := c.Get("anything"); ok {
		t.Error("empty catalog reported a rule as known")
	}
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0", c.Len())
	}
}

// @ac AC-03
// AC-03 (catalog half): Get returns (zero, false) for unknown ids and
// on a nil catalog — the contract the failed-rules handler relies on
// to fall back to title=rule_id, category="".
func TestRuleCatalog_UnknownAndNil_FallbackContract(t *testing.T) {
	t.Run("api-host-compliance/AC-03", func(t *testing.T) {
		c := testCatalog()
		if m, ok := c.Get("no_such_rule"); ok || m != (RuleMeta{}) {
			t.Errorf("Get(unknown) = (%+v, %v), want (zero, false)", m, ok)
		}

		var nilCatalog *RuleCatalog
		if m, ok := nilCatalog.Get("sshd_disable_root_login"); ok || m != (RuleMeta{}) {
			t.Errorf("nil catalog Get = (%+v, %v), want (zero, false)", m, ok)
		}
		if nilCatalog.Len() != 0 {
			t.Errorf("nil catalog Len = %d, want 0", nilCatalog.Len())
		}
	})
}
