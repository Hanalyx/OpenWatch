// RuleCatalog — in-memory kensa rule id -> {title, category, severity}
// lookup for read-path endpoints (the failed-rules listing resolves
// titles through it). Built once at boot from the same kensa-rules
// corpus the scan wiring loads; read-only after construction, so it is
// safe for concurrent handler use without locking.
//
// internal/kensa is the only package allowed to import the upstream
// kensa module — consumers depend on this wrapper, never on
// github.com/Hanalyx/kensa directly.
//
// Spec: api-host-compliance.
package kensa

import (
	"fmt"

	kensaapi "github.com/Hanalyx/kensa/api"
	pkgkensa "github.com/Hanalyx/kensa/pkg/kensa"
)

// RuleMeta is the catalog projection of one kensa rule.
type RuleMeta struct {
	Title       string
	Category    string
	Severity    string
	Description string
}

// RuleCatalog maps kensa rule ids to their display metadata.
// Immutable after construction.
type RuleCatalog struct {
	rules map[string]RuleMeta
}

// NewRuleCatalogFromRules builds a catalog from already-loaded rules.
// Nil entries and empty ids are skipped. Exported so tests (and any
// future in-process loader reuse) can construct a catalog without the
// on-disk corpus.
func NewRuleCatalogFromRules(rules []*kensaapi.Rule) *RuleCatalog {
	m := make(map[string]RuleMeta, len(rules))
	for _, r := range rules {
		if r == nil || r.ID == "" {
			continue
		}
		m[r.ID] = RuleMeta{
			Title:       r.Title,
			Category:    r.Category,
			Severity:    r.Severity,
			Description: r.Description,
		}
	}
	return &RuleCatalog{rules: m}
}

// NewRuleCatalog loads the rule corpus from rulesDir (empty selects
// the kensa-rules package default path) and builds the catalog. Same
// loader the production ScanFunc uses.
func NewRuleCatalog(rulesDir string) (*RuleCatalog, error) {
	rules, err := pkgkensa.LoadRules(rulesDir, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("kensa: load rule corpus for catalog: %w", err)
	}
	return NewRuleCatalogFromRules(rules), nil
}

// Get returns the metadata for a rule id. The boolean reports whether
// the id is known. Nil-safe: a nil catalog reports every id unknown,
// so callers can fall back to the rule id without wiring checks.
func (c *RuleCatalog) Get(id string) (RuleMeta, bool) {
	if c == nil {
		return RuleMeta{}, false
	}
	m, ok := c.rules[id]
	return m, ok
}

// Len reports the number of cataloged rules.
func (c *RuleCatalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.rules)
}
