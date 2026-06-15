package kensa

import (
	"fmt"
	"sort"

	kensaapi "github.com/Hanalyx/kensa/api"
	pkgkensa "github.com/Hanalyx/kensa/pkg/kensa"
)

// RuleLibrary is the in-memory, display-oriented projection of the full
// kensa rule corpus that backs the rule-library browser (/api/v1/rules).
// Unlike RuleCatalog (a lightweight id -> {title, category, severity}
// lookup for read-path title resolution), each entry carries the
// NORMALIZED framework references and a remediation summary the browser
// needs — derived once at boot from the heterogeneous raw rule schema, so
// no consumer re-parses it.
//
// Built once at boot from the same kensa-rules corpus the scan wiring
// loads; read-only after construction, safe for concurrent handler use.
//
// NOTE: per the package contract, only internal/kensa imports the upstream
// kensa module — the exported RuleListItem carries plain Go types so the
// HTTP handler maps it without touching github.com/Hanalyx/kensa.
//
// Spec: api-rules.
type RuleLibrary struct {
	rules []RuleListItem
}

// RuleListItem is one normalized rule for the library browser.
type RuleListItem struct {
	ID          string
	Title       string
	Description string
	Severity    string // critical | high | medium | low
	Category    string
	Tags        []string
	// FrameworkRefs maps framework_id -> control ids, in the SAME shape as
	// scan_results.framework_refs (e.g. {"cis_rhel9": ["6.3.1.4"],
	// "stig_rhel9": ["V-258151"], "nist_800_53": ["AU-2", "AU-3"]}), so the
	// UI renders the same tags it renders on the scan-detail page.
	FrameworkRefs map[string][]string
	Remediation   RemediationSummary
}

// RemediationSummary is the host-independent remediation descriptor shown
// in the library's Remediation column. It reports the default
// implementation's mechanism and whether a fix is automated.
//
// NOTE: Kensa's public rule schema exposes no explicit "requires reboot"
// or risk-level field (only the mechanism + reload/restart hints), so this
// summary intentionally stops at mechanism + manual. A richer descriptor
// is pending a Kensa-side read model (see the boundary doc / Kensa issue).
type RemediationSummary struct {
	// Mechanism is the default implementation's remediation mechanism
	// (e.g. "config_set_dropin", "service_enabled", "manual"), or "" when
	// the rule declares no remediation.
	Mechanism string
	// Manual is true when there is no automated mechanism (mechanism is
	// "manual" or empty), so the UI can distinguish atomic fixes.
	Manual bool
}

// NewRuleLibrary loads the rule corpus from rulesDir and normalizes it.
func NewRuleLibrary(rulesDir string) (*RuleLibrary, error) {
	raw, err := pkgkensa.LoadRules(rulesDir, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("kensa: load rule corpus for library: %w", err)
	}
	return NewRuleLibraryFromRules(raw), nil
}

// NewRuleLibraryFromRules builds the library from already-loaded rules
// (used by tests with fixtures).
func NewRuleLibraryFromRules(raw []*kensaapi.Rule) *RuleLibrary {
	out := make([]RuleListItem, 0, len(raw))
	for _, r := range raw {
		if r == nil || r.ID == "" {
			continue
		}
		out = append(out, RuleListItem{
			ID:            r.ID,
			Title:         r.Title,
			Description:   r.Description,
			Severity:      r.Severity,
			Category:      r.Category,
			Tags:          r.Tags,
			FrameworkRefs: normalizeFrameworkRefs(r.References),
			Remediation:   summarizeRemediation(r.Implementations),
		})
	}
	// Stable order: category then rule id, so the browser is deterministic.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return &RuleLibrary{rules: out}
}

// NewRuleLibraryFromItems builds a library from already-normalized items.
// It takes kensa-owned types (no upstream kensa import needed), so callers
// outside internal/kensa — chiefly test fixtures — can construct one
// without the on-disk corpus. Items are sorted like the corpus loader.
func NewRuleLibraryFromItems(items []RuleListItem) *RuleLibrary {
	out := append([]RuleListItem(nil), items...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return &RuleLibrary{rules: out}
}

// List returns the normalized rules (nil-safe).
func (l *RuleLibrary) List() []RuleListItem {
	if l == nil {
		return nil
	}
	return l.rules
}

// Len reports the number of rules (nil-safe).
func (l *RuleLibrary) Len() int {
	if l == nil {
		return 0
	}
	return len(l.rules)
}

// normalizeFrameworkRefs flattens the raw, heterogeneous rule References
// map into framework_id -> control ids. The raw shapes are:
//
//	cis:         {rhel9: {section: "6.3.1.4", level: "L1", ...}}  -> cis_rhel9: ["6.3.1.4"]
//	stig:        {rhel9: {vuln_id: "V-258151", stig_id: ...}}     -> stig_rhel9: ["V-258151"]
//	nist_800_53: ["AU-2", "AU-3"]                                 -> nist_800_53: ["AU-2", "AU-3"]
//
// A nested per-distro map becomes "<framework>_<distro>"; the control id
// is the first recognized id field (section, then vuln_id, then stig_id,
// then control_id/id). A top-level array is taken verbatim. Control slices
// are deduped and sorted for deterministic output.
func normalizeFrameworkRefs(refs map[string]interface{}) map[string][]string {
	out := map[string][]string{}
	add := func(key, control string) {
		if key == "" || control == "" {
			return
		}
		for _, c := range out[key] {
			if c == control {
				return
			}
		}
		out[key] = append(out[key], control)
	}
	for framework, v := range refs {
		switch val := v.(type) {
		case []interface{}:
			for _, e := range val {
				if s, ok := e.(string); ok {
					add(framework, s)
				}
			}
		case map[string]interface{}:
			for distro, sub := range val {
				key := framework + "_" + distro
				switch o := sub.(type) {
				case map[string]interface{}:
					add(key, pickControlID(o))
				case []interface{}:
					for _, e := range o {
						if s, ok := e.(string); ok {
							add(key, s)
						}
					}
				case string:
					add(framework, o) // flat scalar value (rare)
				}
			}
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// pickControlID returns the recognizable control identifier from a nested
// reference object, preferring section (CIS), then vuln_id (STIG, present
// corpus-wide), then stig_id / control_id / id.
func pickControlID(o map[string]interface{}) string {
	for _, k := range []string{"section", "vuln_id", "stig_id", "control_id", "id"} {
		if s, ok := o[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// summarizeRemediation reads the default implementation's remediation
// mechanism (host-independent — the library has no host context).
func summarizeRemediation(imps []kensaapi.Implementation) RemediationSummary {
	mech := ""
	for _, im := range imps {
		if im.Default {
			mech = im.Remediation.Mechanism
			break
		}
	}
	if mech == "" && len(imps) > 0 {
		mech = imps[0].Remediation.Mechanism
	}
	return RemediationSummary{
		Mechanism: mech,
		Manual:    mech == "" || mech == "manual",
	}
}
