package notifyfeed

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
)

// Channel is an alertrouter.Channel that fans each alert into the in-app feed —
// one durable row per active recipient. Registered at boot alongside the
// stdout/Slack/email channels, so every alert the engine already classifies
// (host_unreachable, host_recovered, drift_major/minor/improvement) lights up
// the bell for free. Later slices add a transaction-log projector for
// rule-level regressions. Spec: system-notifications.
type Channel struct {
	store *Store
}

// NewChannel returns the in-app notification channel.
func NewChannel(store *Store) *Channel {
	return &Channel{store: store}
}

// Name identifies the channel in router metrics + logs.
func (c *Channel) Name() string { return "in-app" }

// Send fans the alert into one in-app notification per active recipient, in a
// single statement (RecordFanout) so an alert is one DB round-trip rather than
// one per user.
func (c *Channel) Send(ctx context.Context, alert alertrouter.Alert) error {
	return c.store.RecordFanout(ctx, notificationFromAlert(alert))
}

// notificationFromAlert maps an alert to the per-user notification template
// (UserID filled in per recipient). A host-scoped alert deep-links to the host;
// fleet/system alerts carry no host link.
func notificationFromAlert(a alertrouter.Alert) Notification {
	n := Notification{
		Kind:       string(a.Type),
		Severity:   string(a.Severity),
		Title:      a.Title,
		Body:       a.Body,
		GroupKey:   a.DedupKey(),
		OccurredAt: a.OccurredAt,
	}
	if a.HostID != uuid.Nil {
		h := a.HostID
		n.HostID = &h
		n.Link = "/hosts/" + a.HostID.String()
	}
	return n
}
