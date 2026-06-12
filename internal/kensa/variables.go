// VariableCatalog — the corpus-used kensa rule-template variables with
// their built-in defaults, for the Settings scan-variables UI and the
// PUT validation path.
//
// kensa.BuiltInVars ships ~29 defaults but only the variables that
// corpus rules actually reference are rendered or accepted as
// overrides (the plan's "20 used variables; don't render the unused
// 9"). Three defaults are organization-specific placeholders the
// operator should always review; ConfigureMe flags them.
//
// internal/kensa is the only package allowed to import the upstream
// kensa module — consumers depend on this wrapper.
//
// Spec: api-system-scan-config v1.1.0.
package kensa

import (
	"fmt"
	"sort"

	pkgkensa "github.com/Hanalyx/kensa/pkg/kensa"
)

// placeholderVars are the organization-specific defaults kensa's
// BuiltInVars doc names as always-review (scans against the shipped
// examples produce technically valid but practically meaningless
// verdicts for their rules).
var placeholderVars = map[string]bool{
	"rsyslog_remote_server": true,
	"chrony_ntp_pool":       true,
	"banner_text":           true,
}

// VariableInfo is one corpus-used variable.
type VariableInfo struct {
	Name    string
	Default string   // kensa built-in default
	Rules   []string // rule ids referencing the variable, sorted
	// ConfigureMe marks organization-specific placeholder defaults.
	ConfigureMe bool
}

// VariableCatalog maps corpus-used variable names to their info.
// Immutable after construction; safe for concurrent handler use.
type VariableCatalog struct {
	vars map[string]VariableInfo
}

// NewVariableCatalog intersects kensa's built-in defaults with the
// variables the corpus at rulesDir actually references. Empty rulesDir
// selects the kensa-rules package default path, same as the scan
// wiring.
func NewVariableCatalog(rulesDir string) (*VariableCatalog, error) {
	defaults, err := pkgkensa.BuiltInVars()
	if err != nil {
		return nil, fmt.Errorf("kensa: built-in vars: %w", err)
	}
	used, err := pkgkensa.RuleVariables(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("kensa: rule variables: %w", err)
	}

	m := make(map[string]VariableInfo, len(used))
	for name, ruleIDs := range used {
		sorted := append([]string(nil), ruleIDs...)
		sort.Strings(sorted)
		m[name] = VariableInfo{
			Name:        name,
			Default:     defaults[name], // "" when a rule references an undefaulted var
			Rules:       sorted,
			ConfigureMe: placeholderVars[name],
		}
	}
	return &VariableCatalog{vars: m}, nil
}

// List returns every corpus-used variable sorted by name.
// Nil-safe: a nil catalog lists nothing.
func (c *VariableCatalog) List() []VariableInfo {
	if c == nil {
		return nil
	}
	out := make([]VariableInfo, 0, len(c.vars))
	for _, v := range c.vars {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Has reports whether name is a corpus-used variable. Nil-safe.
func (c *VariableCatalog) Has(name string) bool {
	if c == nil {
		return false
	}
	_, ok := c.vars[name]
	return ok
}

// Len reports the number of corpus-used variables.
func (c *VariableCatalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.vars)
}

// NewVariableCatalogFromInfos builds a catalog from already-known
// variable infos. Exported for tests (mirrors NewRuleCatalogFromRules)
// so the HTTP fixtures don't need the on-disk corpus.
func NewVariableCatalogFromInfos(infos []VariableInfo) *VariableCatalog {
	m := make(map[string]VariableInfo, len(infos))
	for _, v := range infos {
		if v.Name == "" {
			continue
		}
		m[v.Name] = v
	}
	return &VariableCatalog{vars: m}
}
