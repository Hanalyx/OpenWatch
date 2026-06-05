// Package stdout implements an alertrouter.Channel that logs alerts to
// the structured slog default logger at INFO level.
//
// This is the minimum-viable channel for an operator. Once registered,
// `journalctl -u openwatch -g alertrouter.alert.sent` returns the
// stream of fired alerts. Slack / email / webhook channels follow the
// same Channel interface and live in sibling subpackages — keeping
// this one dependency-free preserves the alertrouter core's
// "no external SDKs" invariant (system-alert-router AC-13).
//
// Spec: system-daemon-orchestration AC-13 (registered at boot).
package stdout

import (
	"context"
	"log/slog"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
)

// Channel writes each alert via slog.InfoContext. The struct itself
// holds no state; one instance per process is enough.
type Channel struct {
	name string
}

// New returns a stdout channel ready for alertrouter.Register.
// channelName is the identifier used in metrics + failure logs;
// defaults to "stdout" when empty.
func New(channelName string) *Channel {
	if channelName == "" {
		channelName = "stdout"
	}
	return &Channel{name: channelName}
}

// Name satisfies alertrouter.Channel.
func (c *Channel) Name() string { return c.name }

// Send writes the alert via slog at INFO with structured attributes.
// Never returns an error — stdout/journald is the operator's last
// resort even if a downstream channel is misbehaving.
func (c *Channel) Send(ctx context.Context, a alertrouter.Alert) error {
	slog.InfoContext(ctx, "alertrouter.alert.sent",
		slog.String("channel", c.name),
		slog.String("alert_type", string(a.Type)),
		slog.String("severity", string(a.Severity)),
		slog.String("host_id", a.HostID.String()),
		slog.String("rule_id", a.RuleID),
		slog.Time("occurred_at", a.OccurredAt),
		slog.String("title", a.Title),
	)
	return nil
}
