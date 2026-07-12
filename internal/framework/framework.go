// Package framework groups the corpus's per-rule framework reference keys
// (host_rule_state.framework_refs) into user-facing FAMILIES and lists them
// for the "default compliance lens" picker.
//
// Corpus keys are either OS-specific baselines (stig_rhel9, cis_ubuntu22, …)
// or OS-agnostic catalogs (nist_800_53, pci_dss_4, srg). A FAMILY is the
// coarse grouping an operator picks (STIG, CIS, …): the key with a trailing
// _<os><version> segment stripped. An OS-agnostic key is its own family.
//
// The score-filter queries (fleet score, hosts list) match a family in SQL
// with the SAME regexp as FamilyOf below — see osSuffixSQL. Keep the two in
// sync: a rule-state is "in family F" when any of its framework_refs keys,
// with the OS suffix stripped, equals F.
package framework

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// osSuffix matches a trailing OS/version segment (e.g. _rhel9, _ubuntu2204).
// Only rhel/ubuntu tokens count as OS suffixes; digits elsewhere
// (nist_800_53, pci_dss_4) are NOT stripped.
var osSuffix = regexp.MustCompile(`_(rhel|ubuntu)[0-9]+$`)

// OSSuffixSQL is the Postgres regexp literal mirroring osSuffix, for the
// score-filter queries. MUST match osSuffix.
const OSSuffixSQL = `_(rhel|ubuntu)[0-9]+$`

// FamilyOf returns the family id for a corpus framework key by stripping a
// trailing OS suffix. A key with no OS suffix is its own family:
//
//	stig_rhel9 -> stig ; cis_ubuntu22 -> cis ; nist_800_53 -> nist_800_53
func FamilyOf(key string) string { return osSuffix.ReplaceAllString(key, "") }

// MatchSQL returns a SQL boolean fragment (for a WHERE clause on a table
// with a framework_refs JSONB column) that is TRUE when:
//   - the bind parameter is NULL (all-rules, no filter), OR
//   - framework_refs has a key equal to the parameter (a specific corpus
//     key, e.g. "stig_rhel9"), OR
//   - framework_refs has a key whose family (OS suffix stripped) equals the
//     parameter (a family id, e.g. "stig" matches stig_rhel9/stig_rhel10/…).
//
// paramRef is the placeholder to use (e.g. "$1", "$2"); it must be a fixed
// literal, never user input. The family regexp mirrors FamilyOf.
func MatchSQL(paramRef string) string {
	return `(` + paramRef + `::text IS NULL OR EXISTS (
			SELECT 1 FROM jsonb_object_keys(framework_refs) AS fk
			 WHERE fk = ` + paramRef + `
			    OR regexp_replace(fk, '` + OSSuffixSQL + `', '') = ` + paramRef + `))`
}

// familyLabels overrides the display label for known families; anything else
// falls back to an upper-cased id.
var familyLabels = map[string]string{
	"stig":        "STIG",
	"cis":         "CIS",
	"srg":         "SRG",
	"nist_800_53": "NIST 800-53",
	"pci_dss_4":   "PCI DSS 4",
}

// Label renders a family id for display.
func Label(id string) string {
	if l, ok := familyLabels[id]; ok {
		return l
	}
	return strings.ToUpper(id)
}

// Family is a user-facing framework grouping with the corpus keys it spans.
type Family struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Keys  []string `json:"keys"`
}

// Service resolves families from the live corpus (host_rule_state).
type Service struct{ pool *pgxpool.Pool }

// NewService builds the resolver.
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Families groups every framework key present in the corpus into families,
// sorted by id. Empty when no host has been scanned yet.
func (s *Service) Families(ctx context.Context) ([]Family, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT k FROM host_rule_state, jsonb_object_keys(framework_refs) AS k`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byID := map[string][]string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		id := FamilyOf(k)
		byID[id] = append(byID[id], k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Family, 0, len(byID))
	for id, ks := range byID {
		sort.Strings(ks)
		out = append(out, Family{ID: id, Label: Label(id), Keys: ks})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
