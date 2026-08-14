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

// benchmarkFamily maps a distro ID onto the upstream distro whose benchmarks
// the host is graded against. An enterprise-Linux rebuild is graded as its
// upstream: Kensa runs the RHEL 9 rules on an AlmaLinux 9 host, so that host's
// STIG lens must resolve to stig_rhel9. Deriving the key from the raw distro id
// asks for stig_almalinux9, which NO rule in the corpus emits, so the lens
// silently matches nothing and the picker drops it entirely -- the operator is
// shown a page with no STIG or CIS option and no hint that either exists.
//
// This is a STAND-IN for a fact Kensa computes and does not publish. Kensa
// resolved the host to an EL platform in order to decide which rules to run;
// features/KN-OW-018 asks it to say so on the scan result. Delete this map when
// that lands rather than extending it -- every entry here is a second copy of
// Kensa's platform gate, and the gate is expected to widen.
//
// Two families are absent ON PURPOSE, and neither is an oversight:
//
//   - Fedora rolls up to the rhel family in host discovery, but it is upstream
//     of RHEL rather than a rebuild of it and has no EL benchmark. Grading a
//     Fedora host against the RHEL 9 STIG would manufacture coverage that does
//     not exist.
//   - Amazon Linux is EL-adjacent and untested here. A wrong mapping grades a
//     host against the wrong benchmark, which is worse than offering no lens.
//
// A distro absent from this map keeps its own id, so it resolves to a key the
// corpus does not emit and no OS-specific lens is offered. That is the honest
// outcome for a platform nobody has verified.
var benchmarkFamily = map[string]string{
	"almalinux": "rhel",
	"centos":    "rhel",
	"ol":        "rhel",
	"oracle":    "rhel",
	"rocky":     "rhel",
}

// BenchmarkFamily normalizes a hosts.os_family value to the distro whose corpus
// keys apply to it. Unknown or empty input is returned lower-cased and
// unchanged.
func BenchmarkFamily(osFamily string) string {
	k := strings.ToLower(strings.TrimSpace(osFamily))
	if up, ok := benchmarkFamily[k]; ok {
		return up
	}
	return k
}

// benchmarkFamilySQL renders BenchmarkFamily as a SQL CASE over the given
// column expression. GENERATED from the same map rather than hand-written, so
// the SQL and Go paths cannot drift -- the drift they replace is exactly how
// this bug shipped: the frontend already mapped almalinux to RHEL for display
// while the query did not, so one page labeled a host "RHEL 9.8" and then
// withheld the RHEL 9 benchmarks from it.
//
// osFamilyExpr must be a fixed literal in code (a bind placeholder or a column
// reference), never user input; the map keys are compile-time constants.
func benchmarkFamilySQL(osFamilyExpr string) string {
	keys := make([]string, 0, len(benchmarkFamily))
	for k := range benchmarkFamily {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic SQL, so the query text is stable
	var b strings.Builder
	b.WriteString("CASE lower(" + osFamilyExpr + ")")
	for _, k := range keys {
		b.WriteString(" WHEN '" + k + "' THEN '" + benchmarkFamily[k] + "'")
	}
	b.WriteString(" ELSE lower(" + osFamilyExpr + ") END")
	return b.String()
}

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
// suffix: the BENCHMARK family concatenated with the major version
// (split_part(os_version,'.',1)) — e.g. rhel+9 = rhel9, ubuntu+22 = ubuntu22.
//
// The family goes through benchmarkFamilySQL rather than a bare lower(), so an
// EL rebuild resolves to its upstream: an almalinux 9.8 host asks for stig_rhel9
// (391 of its rules carry that ref) instead of stig_almalinux9 (which no rule
// carries). See benchmarkFamily for why that mapping is a stand-in.
func OSResolvedMatchSQL(famRef, osFamilyExpr, osVersionExpr string) string {
	return `(` + famRef + `::text IS NULL
			OR framework_refs ? (` + famRef + ` || '_' || ` + benchmarkFamilySQL(osFamilyExpr) + ` || split_part(` + osVersionExpr + `, '.', 1))
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
//
// "The corpus" means the CURRENT corpora (internal/corpus): the rows each
// host's most recent completed scan evaluated. A framework surviving only
// on retired rows drops off the list, which is the point. It would
// otherwise stay selectable as a lens forever, scoring hosts on rules
// nothing evaluates.
func (s *Service) Families(ctx context.Context) ([]Family, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT k FROM host_rule_state_current, jsonb_object_keys(framework_refs) AS k`)
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
