// Package accountpolicy runs the daily host-user password-expiry sweep.
//
// Password expiry is TIME-based: a host user's password becomes "expiring
// soon" or "expired" as days pass, with no change to the host and no scan.
// The OS-intelligence collector already captures each account's derived
// PasswordExpiresAt into host_intelligence_state.snapshot; this sweep reads
// those stored snapshots on a daily tick and raises a re-nag-safe in-app
// notification for each human account within the warn window (or expired).
//
// It mirrors the exception expiry sweep (internal/exception/run.go): a boot
// pass plus a cron tick, best-effort per user.
//
// Spec: system-account-policy v1.0.0.
package accountpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/intelligence/collector"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

const (
	// SweepInterval is the cadence of the expiry sweep. Expiry moves on a
	// day granularity, so daily is the natural cadence.
	SweepInterval = 24 * time.Hour
	// defaultWarnDays is used when the resolved config is 0 (unset).
	defaultWarnDays = 14
	// minHumanUID is the floor for a real login account; UIDs below it —
	// and nobody (65534) — are system/service accounts we never nag about.
	minHumanUID = 1000
	nobodyUID   = 65534
)

// Notifier delivers a password-expiry notification for one host user. daysLeft
// is meaningful only when expired is false. Implemented by the notifyfeed
// GovernanceProjector so this package does not import notifyfeed.
type Notifier interface {
	PasswordExpiring(ctx context.Context, hostID uuid.UUID, username string, daysLeft int, expired bool) error
}

// SecurityConfigLoader resolves the warn-window threshold (satisfied by
// *systemconfig.Store).
type SecurityConfigLoader interface {
	LoadSecurity(ctx context.Context) (systemconfig.SecurityConfig, error)
}

// Service is the password-expiry sweep.
type Service struct {
	pool     *pgxpool.Pool
	notifier Notifier
	config   SecurityConfigLoader
	now      func() time.Time
}

// New constructs the sweep over the snapshot store, the notifier, and the
// config loader.
func New(pool *pgxpool.Pool, notifier Notifier, config SecurityConfigLoader) *Service {
	return &Service{
		pool:     pool,
		notifier: notifier,
		config:   config,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// SweepOnce evaluates every host's collected user snapshot and notifies for
// each human account whose password has expired or falls within the warn
// window. Returns the count of notifications emitted. Best-effort per user: a
// notify error is logged and the sweep continues.
func (s *Service) SweepOnce(ctx context.Context) (int, error) {
	sec, err := s.config.LoadSecurity(ctx)
	if err != nil {
		return 0, fmt.Errorf("accountpolicy: load config: %w", err)
	}
	warnDays := sec.WarnDaysBeforePasswordExpiry
	if warnDays <= 0 {
		warnDays = defaultWarnDays
	}

	rows, err := s.pool.Query(ctx, `SELECT host_id, snapshot FROM host_intelligence_state`)
	if err != nil {
		return 0, fmt.Errorf("accountpolicy: query snapshots: %w", err)
	}
	defer rows.Close()
	type hostSnap struct {
		id  uuid.UUID
		raw []byte
	}
	var snaps []hostSnap
	for rows.Next() {
		var hs hostSnap
		if err := rows.Scan(&hs.id, &hs.raw); err != nil {
			return 0, fmt.Errorf("accountpolicy: scan snapshot: %w", err)
		}
		snaps = append(snaps, hs)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("accountpolicy: iterate snapshots: %w", err)
	}

	now := s.now()
	sent := 0
	for _, hs := range snaps {
		var snap struct {
			Users map[string]collector.UserSnapshot `json:"users"`
		}
		if err := json.Unmarshal(hs.raw, &snap); err != nil {
			slog.WarnContext(ctx, "accountpolicy: unmarshal snapshot", "host_id", hs.id.String(), "err", err.Error())
			continue
		}
		for name, u := range snap.Users {
			notify, daysLeft, expired := pwExpiryDecision(u, now, warnDays)
			if !notify {
				continue
			}
			if err := s.notifier.PasswordExpiring(ctx, hs.id, name, daysLeft, expired); err != nil {
				slog.WarnContext(ctx, "accountpolicy: notify failed",
					"host_id", hs.id.String(), "user", name, "err", err.Error())
				continue
			}
			sent++
		}
	}
	return sent, nil
}

// pwExpiryDecision classifies one user for the sweep — the pure, testable
// core. Returns notify=false for system/service accounts (UID < 1000 or
// nobody), accounts with no expiry policy (PasswordExpiresAt nil), and
// healthy accounts whose expiry is beyond the warn window. Otherwise
// notify=true with the whole-days remaining (negative-or-zero when already
// expired) and the expired flag. Spec system-account-policy AC-01.
func pwExpiryDecision(u collector.UserSnapshot, now time.Time, warnDays int) (notify bool, daysLeft int, expired bool) {
	if u.UID < minHumanUID || u.UID == nobodyUID {
		return false, 0, false
	}
	if u.PasswordExpiresAt == nil {
		return false, 0, false
	}
	exp := *u.PasswordExpiresAt
	expired = !exp.After(now)
	if !expired && exp.After(now.AddDate(0, 0, warnDays)) {
		return false, 0, false // healthy, outside the warn window
	}
	return true, int(exp.Sub(now).Hours() / 24), expired
}
