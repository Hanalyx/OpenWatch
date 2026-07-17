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
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

// OSResolvedMatchSQL returns a SQL boolean fragment (for a WHERE clause on a
// table with a framework_refs JSONB column) that is TRUE when framework_refs
// matches the family in famRef RESOLVED to the host's OWN OS-specific corpus
// key — NOT the union of every OS variant.
//
// This is the correct filter for a PER-HOST compliance score. MatchSQL is
// family-aware and matches ANY key in a family (stig -> stig_rhel9 +
// stig_rhel10 + …); that over-counts a single host, which carries mapped rules
// for several OS benchmarks at once (a RHEL 9 host has stig_rhel9 AND
// stig_rhel10 refs). Grading a RHEL 9 host partly against the RHEL 10 STIG is
// wrong. OSResolvedMatchSQL instead scopes a family to `<family>_<osfamily><major>`
// (stig on a rhel 9.6 host -> stig_rhel9), so the list/summary/fleet score
// matches the host-detail tile.
//
// It is TRUE when:
//   - famRef IS NULL (all rules, no filter), OR
//   - framework_refs has the OS-resolved key `famRef || '_' || <osfamily><major>`
//     (a family scoped to this host's OS: stig -> stig_rhel9), OR
//   - framework_refs has a key equal to famRef itself — which covers an
//     OS-neutral family (nist_800_53, pci_dss_4, srg, whose key carries no OS
//     suffix) and an explicitly-passed specific key (stig_rhel9).
//
// famRef, osFamilyExpr, osVersionExpr are SQL expressions (a bind placeholder
// like "$2", or a column reference like "eff.fam"/"hh.os_family"); they must be
// fixed literals in code, never user input. The OS token mirrors the corpus key
// suffix: lower(os_family) concatenated with the major version
// (split_part(os_version,'.',1)) — e.g. rhel+9 = rhel9, ubuntu+22 = ubuntu22.
func OSResolvedMatchSQL(famRef, osFamilyExpr, osVersionExpr string) string {
	return `(` + famRef + `::text IS NULL
			OR framework_refs ? (` + famRef + ` || '_' || lower(` + osFamilyExpr + `) || split_part(` + osVersionExpr + `, '.', 1))
			OR framework_refs ? ` + famRef + `)`
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

// EffectiveTarget returns the host's effective compliance-target family: its
// host_effective_target value (the host override, else the oldest site-group
// target — migration 0051), falling back to orgDefault when neither is set.
// An empty result means All rules. This is the per-host default lens: a host's
// score defaults to its target instead of the org default.
func (s *Service) EffectiveTarget(ctx context.Context, hostID uuid.UUID, orgDefault string) (string, error) {
	var target *string
	err := s.pool.QueryRow(ctx,
		`SELECT target_framework FROM host_effective_target WHERE host_id = $1`, hostID).Scan(&target)
	if errors.Is(err, pgx.ErrNoRows) {
		return orgDefault, nil
	}
	if err != nil {
		return "", err
	}
	if target != nil && *target != "" {
		return *target, nil
	}
	return orgDefault, nil
}

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
