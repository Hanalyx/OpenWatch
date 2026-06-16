// Production ScanFunc — the live Kensa.Scan binding.
//
// The chain: kensa.LoadRules (once, at construction) -> per-scan host
// lookup -> Kensa.Scan over the in-memory TransportFactory -> field
// copy of kensa's []RuleOutcome into the executor's Result.
//
// The credential is resolved TWICE by design: the executor's
// CredentialBridge resolve is the gate (no-credential / decrypt-fail
// short-circuit + wipe contract, specs AC-07/AC-09/AC-15), while the
// TransportFactory re-resolves the full credential inside Connect —
// the bridge's bytes alone cannot authenticate (no username, no
// passphrase, no password fallback). The ScanFunc therefore ignores
// the bridge's plain bytes.
//
// Construction: kensa v0.3.2's scan-only composition —
// api.New(Config{Scanner: pkg/kensa.NewScanner(), TransportFactory:
// ours}). No engine, store, or signer is constructed; NewScanner is
// stateless and safe for concurrent Scan calls sharing one instance
// (per its doc), so one service serves the whole worker. Remediate on
// this construction errors by design — Phase 7 switches to
// DefaultWithTransportFactory when remediation lands.
//
// Spec: system-kensa-executor v2.3.0 (C-12, C-13, C-14).
package kensa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	kensaapi "github.com/Hanalyx/kensa/api"
	pkgkensa "github.com/Hanalyx/kensa/pkg/kensa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/credential"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
)

// scanService is the slice of kensa's surface the ScanFunc consumes.
// *api.Kensa satisfies it; tests inject fakes.
type scanService interface {
	Scan(ctx context.Context, host kensaapi.HostConfig, rules []*kensaapi.Rule, opts ...kensaapi.RunOption) (*kensaapi.ScanResult, error)
}

// newScanService composes the scan-only Kensa: the standard scanner
// backend over our in-memory TransportFactory. kensa v0.3.2
// pkg/kensa.NewScanner is stateless and concurrency-safe shared.
func newScanService(factory kensaapi.TransportFactory) (scanService, error) {
	return kensaapi.New(kensaapi.Config{
		Scanner:          pkgkensa.NewScanner(),
		TransportFactory: factory,
	})
}

// ScanFuncDeps are the inputs to NewProductionScanFunc.
type ScanFuncDeps struct {
	Pool        *pgxpool.Pool
	Credentials *credential.Service
	// RulesDir is the kensa-rules corpus location. Empty selects the
	// kensa-rules package default path (/usr/share/kensa/rules).
	RulesDir string
	// HostKeyMode + KnownHosts set the dial-time host-key policy.
	HostKeyMode owssh.Mode
	KnownHosts  owssh.KnownHostsStore
	// Variables, when non-nil, returns the operator's variable
	// overrides (systemconfig scan_variables). The corpus is
	// re-loaded with the merged vars whenever the override set
	// changes, so a Settings edit applies to the NEXT scan without a
	// restart. Nil keeps the boot-loaded corpus (built-in defaults).
	Variables func(ctx context.Context) (map[string]string, error)
	// Profiles is the per-host connection memory (nil disables
	// learning). The scan transport reads it to lead with the host's
	// known-good SSH auth method + sudo mode, and writes back what it
	// learns. *connprofile.Store in production.
	Profiles ConnProfile
	// Policy gates whether the credential password may be used for
	// sudo -S (the AllowCredentialSudoPassword kill-switch). nil =>
	// allowed (default-on). Production wires systemconfig LoadSecurity so
	// the scan honors the same switch as the collector/liveness/discovery
	// paths.
	Policy SudoPasswordPolicy
}

// NewProductionScanFunc loads the rule corpus once at construction
// (built-in defaults; LoadRules merges caller vars over BuiltInVars)
// and returns the ScanFunc the worker binds via WithScanFunc. When
// deps.Variables is wired, each scan checks the operator override set
// and re-loads the corpus only when it changed (a fingerprint
// comparison; reload failures keep the last-good corpus so a disk
// blip never bricks scanning).
func NewProductionScanFunc(deps ScanFuncDeps) (ScanFunc, error) {
	rules, err := pkgkensa.LoadRules(deps.RulesDir, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("kensa: load rule corpus: %w", err)
	}
	corpus := &corpusCache{rules: rules, dir: deps.RulesDir}
	factory := &TransportFactory{
		Resolve:  deps.Credentials.Resolve,
		Mode:     deps.HostKeyMode,
		Store:    deps.KnownHosts,
		Profiles: deps.Profiles,
		Policy:   deps.Policy,
	}
	svc, err := newScanService(factory)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, hostID uuid.UUID, policyVersion string, _ []byte) (*Result, FailureReason, error) {
		target, err := loadScanHost(ctx, deps.Pool, hostID)
		if err != nil {
			return nil, ReasonKensaError, err
		}
		scanRules := corpus.current(ctx, deps.Variables)
		started := time.Now().UTC()
		scanRes, err := svc.Scan(ctx, target.hostConfig(hostID), scanRules)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, "", err
			}
			return nil, classifyScanError(err), err
		}
		return &Result{
			HostID:        hostID,
			PolicyVersion: policyVersion,
			StartedAt:     started,
			CompletedAt:   time.Now().UTC(),
			Outcomes:      mapOutcomes(scanRes.Outcomes),
		}, "", nil
	}, nil
}

// scanHost is the host-row slice a scan needs.
type scanHost struct {
	address  string // ip_address text form — no DNS dependency
	port     int
	username string // hosts.username override; "" = credential's
}

func (h scanHost) hostConfig(hostID uuid.UUID) kensaapi.HostConfig {
	return kensaapi.HostConfig{
		Hostname: h.address,
		Port:     h.port,
		User:     h.username,
		// Kensa rules check root-owned state; the factory downgrades
		// sudo when the effective user is already root.
		Sudo: true,
		// FleetID carries the host id to the TransportFactory (and
		// into kensa's own event context). Spec C-15.
		FleetID: hostID.String(),
	}
}

// loadScanHost reads the connection coordinates for an active host.
func loadScanHost(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID) (scanHost, error) {
	var h scanHost
	var username *string
	err := pool.QueryRow(ctx, `
		SELECT host(ip_address), port, username
		FROM hosts
		WHERE id = $1 AND deleted_at IS NULL`, hostID).
		Scan(&h.address, &h.port, &username)
	if errors.Is(err, pgx.ErrNoRows) {
		return h, fmt.Errorf("kensa: host %s not found or deleted", hostID)
	}
	if err != nil {
		return h, fmt.Errorf("kensa: load host %s: %w", hostID, err)
	}
	if username != nil {
		h.username = *username
	}
	return h, nil
}

// mapOutcomes is the kensa -> OpenWatch field copy. No compliance
// logic lives here: kensa's verdict is authoritative (C-14).
func mapOutcomes(in []kensaapi.RuleOutcome) []RuleOutcome {
	out := make([]RuleOutcome, 0, len(in))
	for _, o := range in {
		m := RuleOutcome{
			RuleID:        o.RuleID,
			Status:        mapStatus(o.Status),
			Severity:      o.Severity,
			Evidence:      evidenceJSON(o),
			FrameworkRefs: refsToMap(o.FrameworkRefs),
		}
		if m.Status == StatusSkipped {
			m.SkipReason = o.Detail
		}
		out = append(out, m)
	}
	return out
}

// mapStatus converts kensa's ComplianceStatus (closed enum
// pass|fail|skipped|error) to the executor's ResultStatus. An
// out-of-enum value — impossible today, defensive against a future
// kensa addition — degrades to StatusError rather than fabricating a
// verdict.
func mapStatus(s kensaapi.ComplianceStatus) ResultStatus {
	switch s {
	case kensaapi.CompliancePass:
		return StatusPass
	case kensaapi.ComplianceFail:
		return StatusFail
	case kensaapi.ComplianceSkipped:
		return StatusSkipped
	case kensaapi.ComplianceError:
		return StatusError
	default:
		return StatusError
	}
}

// refsToMap converts kensa's []FrameworkRef into the multi-valued
// framework_id -> control ids map, preserving every control when one
// framework maps a rule more than once (C-14, v2.1.0).
func refsToMap(refs []kensaapi.FrameworkRef) map[string][]string {
	if len(refs) == 0 {
		return nil
	}
	m := make(map[string][]string, len(refs))
	for _, r := range refs {
		m[r.FrameworkID] = append(m[r.FrameworkID], r.ControlID)
	}
	return m
}

// maxEvidenceDetail bounds the human-readable detail captured into
// evidence JSON. Far below MaxEvidenceBytes (10 MiB) — detail is a
// verdict explanation, not a payload dump.
const maxEvidenceDetail = 64 * 1024

// evidenceDoc is the JSON document persisted into the
// transactions/host_rule_state evidence columns. As of kensa v0.4.3 it
// carries the structured per-command CheckEvidence (the reproducible
// proof behind the verdict — exact command, captured output, exit
// status, expected value), not just the human-readable detail string.
// The Compliance tab renders Checks (Formatted/Evidence) and OSCAL is
// reconstructed from these outcomes on demand.
type evidenceDoc struct {
	Detail string                   `json:"detail"`
	Error  string                   `json:"error,omitempty"`
	Checks []kensaapi.CheckEvidence `json:"checks,omitempty"`
}

// evidenceJSON wraps kensa's verdict detail, structured per-command
// evidence, and error (when present) as the JSON document the
// transactions/host_rule_state evidence columns require. Pathological
// totals are still caught by the executor's MaxEvidenceBytes guard
// (C-10/AC-14); kensa already truncates each CheckEvidence field.
func evidenceJSON(o kensaapi.RuleOutcome) []byte {
	detail := o.Detail
	if len(detail) > maxEvidenceDetail {
		detail = detail[:maxEvidenceDetail] + "…(truncated)"
	}
	doc := evidenceDoc{Detail: detail, Checks: o.Evidence}
	if o.Err != nil {
		doc.Error = o.Err.Error()
	}
	b, err := json.Marshal(doc)
	if err != nil {
		// CheckEvidence is plain strings/ints; marshal cannot realistically
		// fail. Belt-and-braces: degrade to a detail-only document.
		return []byte(`{"detail":"evidence marshal failed"}`)
	}
	return b
}

// classifyScanError maps a scan-path failure onto the executor's
// closed FailureReason enum (AC-06).
func classifyScanError(err error) FailureReason {
	switch {
	case errors.Is(err, owssh.ErrHostKeyUnknown), errors.Is(err, owssh.ErrHostKeyMismatch):
		return ReasonHostKeyUnknown
	case errors.Is(err, owssh.ErrDialTimeout):
		return ReasonTimeout
	default:
		// Connect/auth/kensa-internal failures: the generic engine
		// class; the error text rides the audit detail.
		return ReasonKensaError
	}
}

// corpusCache holds the loaded rule corpus keyed by the operator
// override fingerprint. One mutex-guarded slot: scans are serialized
// per worker and override edits are rare, so anything fancier buys
// nothing.
type corpusCache struct {
	mu          sync.Mutex
	rules       []*kensaapi.Rule
	fingerprint string // "" = built-in defaults (boot load)
	dir         string
}

// current returns the corpus matching the operator's current override
// set, re-loading when the set changed since the last scan. Any
// failure (override load OR corpus reload) keeps the last-good corpus
// — scanning never stops on a config-read blip; the warning names the
// cause.
func (c *corpusCache) current(ctx context.Context, vars func(ctx context.Context) (map[string]string, error)) []*kensaapi.Rule {
	c.mu.Lock()
	defer c.mu.Unlock()
	if vars == nil {
		return c.rules
	}
	overrides, err := vars(ctx)
	if err != nil {
		slog.WarnContext(ctx, "kensa: scan variables load failed; keeping current corpus",
			slog.String("error", err.Error()))
		return c.rules
	}
	fp := varsFingerprint(overrides)
	if fp == c.fingerprint {
		return c.rules
	}
	reloaded, err := pkgkensa.LoadRules(c.dir, nil, overrides)
	if err != nil {
		slog.WarnContext(ctx, "kensa: corpus reload with overrides failed; keeping current corpus",
			slog.String("error", err.Error()))
		return c.rules
	}
	c.rules = reloaded
	c.fingerprint = fp
	slog.InfoContext(ctx, "kensa: corpus reloaded with operator variable overrides",
		slog.Int("override_count", len(overrides)), slog.Int("rules", len(reloaded)))
	return c.rules
}

// varsFingerprint is a stable identity for an override map.
func varsFingerprint(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte(';')
	}
	return b.String()
}
