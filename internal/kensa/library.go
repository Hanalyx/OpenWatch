package kensa

import (
	"fmt"
	"sort"

	kensaapi "github.com/Hanalyx/kensa/api"
	pkgkensa "github.com/Hanalyx/kensa/pkg/kensa"
)

// RuleLibrary is the in-memory, display-oriented projection of the full
// kensa rule corpus that backs the rule-library browser (/api/v1/rules).
// It is built once at boot from kensa's PUBLIC rule read model
// (pkg/kensa.LoadRuleSummaries, kensa >= v0.4.3): kensa owns the
// normalization of the heterogeneous raw rule schema (framework references
// via internal/mappings, the remediation summary), so this package no
// longer re-parses it — it only re-shapes the result into plain Go types
// the HTTP handler can consume without importing the upstream module.
//
// Read-only after construction, safe for concurrent handler use.
//
// Spec: api-rules.
type RuleLibrary struct {
	rules []RuleListItem
}

// RuleListItem is one normalized rule for the library browser, carrying
// plain Go types only (no upstream kensa types leak past internal/kensa).
type RuleListItem struct {
	ID          string
	Title       string
	Description string
	Severity    string // critical | high | medium | low
	Category    string
	Tags        []string
	// FrameworkRefs maps framework_id -> control ids, grouped from kensa's
	// canonical normalized refs — the SAME framework_id scheme the scanner
	// puts on scan results (e.g. {"cis_rhel9": ["6.3.1.4"], "stig_rhel9":
	// ["V-258151"]}), so the UI renders the same tags as the scan-detail page.
	FrameworkRefs map[string][]string
	// Transactional reports whether the rule's apply path is a capturable,
	// atomic transaction — the "atomic" remediation signal.
	Transactional bool
	Remediation   RemediationSummary
}

// RemediationSummary is the host-independent remediation descriptor from
// kensa's read model (facts only). Risk level is intentionally absent —
// kensa classifies it as operator policy, owned by OpenWatch.
type RemediationSummary struct {
	// Available reports whether the rule has an automated (non-manual)
	// remediation in any implementation.
	Available bool
	// Mechanisms are the distinct remediation mechanisms across all
	// implementations (e.g. "config_set", "service_enabled"), sorted.
	Mechanisms []string
	// RestartsServices are the distinct services the remediation reloads or
	// restarts — a signal that applying the rule will bounce a service.
	RestartsServices []string
	// RebootBehavior is kensa's derivable reboot signal: "boot-param" (a
	// staged boot/grub change, pending until the operator reboots) or
	// "none". It is NOT a complete "requires reboot" answer (change-specific
	// reboots need an authored rule-schema field, deferred upstream).
	RebootBehavior string
}

// NewRuleLibrary loads the rule corpus from rulesDir via kensa's read model
// and re-shapes it.
func NewRuleLibrary(rulesDir string) (*RuleLibrary, error) {
	summaries, err := pkgkensa.LoadRuleSummaries(rulesDir, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("kensa: load rule summaries: %w", err)
	}
	out := make([]RuleListItem, 0, len(summaries))
	for _, s := range summaries {
		if s.ID == "" {
			continue
		}
		out = append(out, fromSummary(s))
	}
	sortRules(out)
	return &RuleLibrary{rules: out}, nil
}

// NewRuleLibraryFromItems builds a library from already-shaped items. It
// takes kensa-owned plain types (no upstream kensa import needed), so
// callers outside internal/kensa — chiefly test fixtures — can construct
// one without the on-disk corpus. Items are sorted like the loader.
func NewRuleLibraryFromItems(items []RuleListItem) *RuleLibrary {
	out := append([]RuleListItem(nil), items...)
	sortRules(out)
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

// fromSummary re-shapes a kensa RuleSummary into a RuleListItem.
func fromSummary(s pkgkensa.RuleSummary) RuleListItem {
	return RuleListItem{
		ID:            s.ID,
		Title:         s.Title,
		Description:   s.Description,
		Severity:      s.Severity,
		Category:      s.Category,
		Tags:          s.Tags,
		FrameworkRefs: groupRefs(s.FrameworkRefs),
		Transactional: s.Transactional,
		Remediation: RemediationSummary{
			Available:        s.Remediation.Available,
			Mechanisms:       s.Remediation.Mechanisms,
			RestartsServices: s.Remediation.RestartsServices,
			RebootBehavior:   s.Remediation.RebootBehavior,
		},
	}
}

// groupRefs groups kensa's already-normalized framework refs by framework
// id into framework_id -> sorted control ids (the wire shape).
func groupRefs(refs []kensaapi.FrameworkRef) map[string][]string {
	out := map[string][]string{}
	for _, r := range refs {
		if r.FrameworkID == "" || r.ControlID == "" {
			continue
		}
		out[r.FrameworkID] = append(out[r.FrameworkID], r.ControlID)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// sortRules orders by category then rule id for a deterministic browser.
func sortRules(rules []RuleListItem) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Category != rules[j].Category {
			return rules[i].Category < rules[j].Category
		}
		return rules[i].ID < rules[j].ID
	})
}
