package kensa

import (
	"context"
	"errors"
	"fmt"
	"time"

	kensaapi "github.com/Hanalyx/kensa/api"
	"github.com/google/uuid"
)

// PlanFunc previews what remediating one rule on one host would do, without
// changing anything.
//
// This is the half of the operator's question that the transaction journal
// cannot answer. The journal explains a fix after it ran; a plan explains one
// before it does. Kensa's Plan connects to the host, captures pre-state and
// returns the apply steps, the validators and the rollback plan, all read-only.
type PlanFunc func(ctx context.Context, hostID uuid.UUID, ruleID string) (*RemediationPlan, FailureReason, error)

// RemediationPlan is the OpenWatch-side view of a kensa Plan.
//
// Everything here is already human-readable in the Kensa contract:
// StepPreview.Summary is documented with the example "Set PermitRootLogin=no
// in sshd_config.d/00-kensa.conf". The one thing that is not is PreStates,
// whose Data is mechanism-specific and opaque, so the captured values are
// deliberately absent until pkg/kensa.DescribePreState lands
// (features/KN-OW-016). Showing which steps captured something is honest;
// guessing at what it means is not.
type RemediationPlan struct {
	PlanID  uuid.UUID
	RuleID  string
	Steps   []PlanStep
	Checks  []PlanCheck
	Undo    []PlanUndo
	CanUndo int
	// Warnings are Kensa's own operator-facing notices, e.g. that the rule is
	// transactional:false and therefore cannot be rolled back as a unit.
	Warnings []string
	// Transactional is false when the rule's steps are not all-or-nothing.
	Transactional bool
	// ControlChannelSensitive is true when a step touches SSH, networking, PAM
	// or firewall state. Kensa arms a deadman timer before applying such a
	// transaction, which is the difference between a risky fix and one that
	// can lock the operator out of the host they are fixing.
	ControlChannelSensitive bool
	EstimatedSeconds        float64
	CapturedAt              time.Time
}

// PlanStep is one apply step that would run.
type PlanStep struct {
	Index      int
	Mechanism  string
	Summary    string
	Capturable bool
}

// PlanCheck is one validator that would run after apply.
type PlanCheck struct {
	Name    string
	Summary string
}

// PlanUndo is how one apply step would be reversed.
type PlanUndo struct {
	Index     int
	Mechanism string
	Summary   string
}

// planService is the slice of kensa's surface the plan closure consumes.
type planService interface {
	Plan(ctx context.Context, host kensaapi.HostConfig, rule *kensaapi.Rule) (*kensaapi.Plan, error)
}

func makePlan(deps RemediateFuncDeps, corpus *corpusCache, svc planService) PlanFunc {
	return func(ctx context.Context, hostID uuid.UUID, ruleID string) (*RemediationPlan, FailureReason, error) {
		target, err := loadScanHost(ctx, deps.Pool, hostID)
		if err != nil {
			return nil, ReasonKensaError, err
		}
		rule := findRule(corpus.current(ctx, deps.Variables), ruleID)
		if rule == nil {
			return nil, ReasonKensaError, fmt.Errorf("kensa: rule %q not in corpus", ruleID)
		}
		p, err := svc.Plan(ctx, target.hostConfig(hostID), rule)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, "", err
			}
			// Planning reaches the host over SSH, so it fails the same ways a
			// scan does: unreachable, auth, sudo. Reuse that classification
			// rather than reporting every failure as an engine fault.
			return nil, classifyScanError(err), err
		}
		return mapPlan(p, ruleID), "", nil
	}
}

func mapPlan(p *kensaapi.Plan, ruleID string) *RemediationPlan {
	out := &RemediationPlan{
		PlanID:                  p.ID,
		RuleID:                  ruleID,
		Warnings:                p.Warnings,
		Transactional:           p.Transactional,
		ControlChannelSensitive: p.ControlChannelSensitive,
		EstimatedSeconds:        p.EstimatedDuration.Seconds(),
		CapturedAt:              p.CreatedAt,
	}
	for _, s := range p.ApplySteps {
		out.Steps = append(out.Steps, PlanStep{
			Index: s.Index, Mechanism: s.Mechanism,
			Summary: s.Summary, Capturable: s.Capturable,
		})
	}
	for _, v := range p.Validators {
		out.Checks = append(out.Checks, PlanCheck{Name: v.Name, Summary: v.Summary})
	}
	for _, r := range p.RollbackPlan {
		out.Undo = append(out.Undo, PlanUndo{
			Index: r.Index, Mechanism: r.Mechanism, Summary: r.Summary,
		})
	}
	// How much of this fix is reversible, counted from what Kensa captured
	// rather than from the rule's own claim about itself.
	for _, ps := range p.PreStates {
		if ps.Capturable {
			out.CanUndo++
		}
	}
	return out
}
