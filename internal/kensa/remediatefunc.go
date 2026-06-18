// Remediation execution wiring (Phase 7, Tier A free-core). Mirrors
// scanfunc.go: where the scan path composes the scan-only Kensa
// (api.New{Scanner, TransportFactory}), the remediation path composes the
// FULL Kensa via pkg/kensa.DefaultWithTransportFactory, which adds the engine,
// the SQLite transaction store (rollback pre-state), the signer, and the log -
// while still driving execution over OUR credential-resolved, apply-enabled
// TransportFactory (api.Kensa.Remediate/Rollback both Connect via
// config.TransportFactory).
//
// This file is pure wiring + mapping; it never decides compliance. Kensa
// applies each rule as a Capture -> Apply -> Validate -> Commit transaction and
// auto-restores pre-state on validation failure.
//
// Spec: system-kensa-executor (remediation), api-remediation.
package kensa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	kensaapi "github.com/Hanalyx/kensa/api"
	pkgkensa "github.com/Hanalyx/kensa/pkg/kensa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/credential"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
)

// RemediateFunc applies a single rule on a host and returns the per-rule
// transaction outcomes. Bound onto the Executor via WithRemediateFunc and
// driven by the remediation worker.
type RemediateFunc func(ctx context.Context, hostID uuid.UUID, ruleID string) (*RemediationRunResult, FailureReason, error)

// RollbackFunc reverts a previously-committed transaction by its Kensa
// transaction id, using pre-state from the SQLite transaction log.
type RollbackFunc func(ctx context.Context, hostID uuid.UUID, txnID uuid.UUID) (*RollbackRunResult, FailureReason, error)

// RemediationRunResult is the OpenWatch-side view of a kensa
// RemediationResult: one entry per transaction the engine ran for the rule.
type RemediationRunResult struct {
	HostID       uuid.UUID
	RuleID       string
	Transactions []RemediationTxn
	StartedAt    time.Time
	CompletedAt  time.Time
}

// RemediationTxn is one Kensa transaction outcome (committed / rolled_back /
// partially_applied / errored), with its signed evidence captured for the
// remediation_transactions journal.
type RemediationTxn struct {
	TxnID    uuid.UUID
	Status   string
	Evidence json.RawMessage
	Err      string
}

// RollbackRunResult is the OpenWatch-side view of a kensa RollbackResult.
type RollbackRunResult struct {
	Status   string // rolled_back | partially_restored | failed
	Evidence json.RawMessage
	Err      string
}

// remediateService is the slice of kensa's surface the remediation closures
// consume; the embedded *api.Kensa on pkg/kensa.Service satisfies it.
type remediateService interface {
	Remediate(ctx context.Context, host kensaapi.HostConfig, rules []*kensaapi.Rule, opts ...kensaapi.RunOption) (*kensaapi.RemediationResult, error)
	Rollback(ctx context.Context, host kensaapi.HostConfig, txnID uuid.UUID) (*kensaapi.RollbackResult, error)
}

// RemediateFuncDeps mirror ScanFuncDeps and add StorePath (the SQLite
// transaction log location - must be durable so rollback pre-state survives a
// restart).
type RemediateFuncDeps struct {
	Pool        *pgxpool.Pool
	Credentials *credential.Service
	RulesDir    string
	HostKeyMode owssh.Mode
	KnownHosts  owssh.KnownHostsStore
	Variables   func(ctx context.Context) (map[string]string, error)
	Profiles    ConnProfile
	Policy      SudoPasswordPolicy
	// StorePath is the kensa SQLite transaction-log path. Empty defaults to
	// kensa's ".kensa/results.db" in the working dir (dev-only); production
	// MUST set a durable path so rollback pre-state survives restarts.
	StorePath string
}

// NewProductionRemediateFunc loads the rule corpus and composes the full Kensa
// service over our credential-resolved, APPLY-enabled TransportFactory,
// returning the remediate + rollback closures the worker binds.
func NewProductionRemediateFunc(ctx context.Context, deps RemediateFuncDeps) (RemediateFunc, RollbackFunc, error) {
	rules, err := pkgkensa.LoadRules(deps.RulesDir, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("kensa: load rule corpus: %w", err)
	}
	corpus := &corpusCache{rules: rules, dir: deps.RulesDir}
	factory := &TransportFactory{
		Resolve:  deps.Credentials.Resolve,
		Mode:     deps.HostKeyMode,
		Store:    deps.KnownHosts,
		Profiles: deps.Profiles,
		Policy:   deps.Policy,
		// Remediation mutates the host; the transport must permit
		// control-channel-sensitive (apply) operations.
		Apply: true,
	}
	svc, err := pkgkensa.DefaultWithTransportFactory(ctx, deps.StorePath, factory)
	if err != nil {
		return nil, nil, fmt.Errorf("kensa: compose remediation service: %w", err)
	}
	return makeRemediate(deps, corpus, svc), makeRollback(deps, svc), nil
}

func makeRemediate(deps RemediateFuncDeps, corpus *corpusCache, svc remediateService) RemediateFunc {
	return func(ctx context.Context, hostID uuid.UUID, ruleID string) (*RemediationRunResult, FailureReason, error) {
		target, err := loadScanHost(ctx, deps.Pool, hostID)
		if err != nil {
			return nil, ReasonKensaError, err
		}
		rule := findRule(corpus.current(ctx, deps.Variables), ruleID)
		if rule == nil {
			return nil, ReasonKensaError, fmt.Errorf("kensa: rule %q not in corpus", ruleID)
		}
		started := time.Now().UTC()
		res, err := svc.Remediate(ctx, target.hostConfig(hostID), []*kensaapi.Rule{rule})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, "", err
			}
			return nil, classifyScanError(err), err
		}
		return &RemediationRunResult{
			HostID:       hostID,
			RuleID:       ruleID,
			Transactions: mapTxns(res.Transactions),
			StartedAt:    started,
			CompletedAt:  time.Now().UTC(),
		}, "", nil
	}
}

func makeRollback(deps RemediateFuncDeps, svc remediateService) RollbackFunc {
	return func(ctx context.Context, hostID uuid.UUID, txnID uuid.UUID) (*RollbackRunResult, FailureReason, error) {
		target, err := loadScanHost(ctx, deps.Pool, hostID)
		if err != nil {
			return nil, ReasonKensaError, err
		}
		res, err := svc.Rollback(ctx, target.hostConfig(hostID), txnID)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, "", err
			}
			return nil, classifyScanError(err), err
		}
		status := "rolled_back"
		if !res.Success {
			status = "failed"
		} else if res.PartialRestore {
			status = "partially_restored"
		}
		ev, _ := json.Marshal(res)
		out := &RollbackRunResult{Status: status, Evidence: ev}
		if !res.Success {
			out.Err = res.Detail
		}
		return out, "", nil
	}
}

// findRule returns the *Rule whose id matches, or nil.
func findRule(rules []*kensaapi.Rule, ruleID string) *kensaapi.Rule {
	for _, r := range rules {
		if r.ID == ruleID {
			return r
		}
	}
	return nil
}

// mapTxns copies kensa TransactionResults into the OpenWatch journal shape.
func mapTxns(in []kensaapi.TransactionResult) []RemediationTxn {
	out := make([]RemediationTxn, 0, len(in))
	for _, t := range in {
		txn := RemediationTxn{
			TxnID:    t.TransactionID,
			Status:   string(t.Status),
			Evidence: txnEvidence(t),
		}
		if t.Error != nil {
			txn.Err = friendlyTxnErr(t.Error.Error())
		}
		out = append(out, txn)
	}
	return out
}

// friendlyTxnErr translates kensa's internal preflight error
// (`mechanism "X" is not registered`) into an operator-facing message. kensa
// v0.5.0 keeps its apply-mechanism handlers in internal/handlers/* and registers
// them only via internal blank imports, so an external Go consumer (OpenWatch)
// cannot register them and Remediate fails preflight before any host change.
// Tracked upstream; lifts with a kensa release that exposes a public handler
// bundle. See docs/engineering/remediation_core_plan.md.
func friendlyTxnErr(raw string) string {
	if strings.Contains(raw, "not registered") {
		return "Remediation engine unavailable in this build: the bundled Kensa version does not register host-mutation handlers for external callers (kensa v0.5.0 limitation). No host change was attempted."
	}
	return raw
}

// txnEvidence marshals the signed evidence envelope (or a transaction
// summary) for the journal.
func txnEvidence(t kensaapi.TransactionResult) json.RawMessage {
	if t.Envelope != nil {
		if b, err := json.Marshal(t.Envelope); err == nil {
			return b
		}
	}
	b, _ := json.Marshal(map[string]any{
		"transaction_id": t.TransactionID.String(),
		"status":         string(t.Status),
		"steps":          len(t.Steps),
	})
	return b
}
