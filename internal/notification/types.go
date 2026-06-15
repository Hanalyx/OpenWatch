// Package notification manages operator-configured alert-delivery
// channels (Slack, generic webhook). It owns the encrypted-at-rest
// channel store and the alertrouter.Channel adapter that fans fired
// alerts out to every enabled, tag-matching channel.
//
// Secret handling: a channel's target (Slack/webhook URL + optional
// bearer token) is encrypted with the shared AES-256-GCM data key
// (internal/secretkey) before it touches a column, and is never returned
// by the API. The list/read path renders a non-secret target_hint (the
// URL host) instead. Outbound delivery is SSRF-guarded: only https URLs
// to public hosts are dialed.
//
// Spec: system-notifications, api-notifications.
package notification

import (
	"time"

	"github.com/google/uuid"
)

// ChannelType enumerates the delivery backends this slice ships. Email
// (smtp) lands in a follow-up; the DB CHECK constraint mirrors this set.
type ChannelType string

const (
	TypeSlack   ChannelType = "slack"
	TypeWebhook ChannelType = "webhook"
)

// IsValid reports whether t is a supported channel type.
func (t ChannelType) IsValid() bool {
	return t == TypeSlack || t == TypeWebhook
}

// Config is the decrypted, in-process-only secret payload for a channel.
// It is never serialized to the API or logged.
type Config struct {
	// URL is the Slack incoming-webhook URL or the generic webhook
	// endpoint. Must be https to a public host (SSRF guard).
	URL string `json:"url"`
	// Token, when set (webhook only), is sent as an Authorization:
	// Bearer header. Optional.
	Token string `json:"token,omitempty"`
}

// Channel is a stored delivery channel. Config is populated only on the
// paths that need the secret (delivery, test); list/read leave it zero.
type Channel struct {
	ID         uuid.UUID
	Type       ChannelType
	Name       string
	Enabled    bool
	TargetHint string // non-secret URL host, for display
	TagFilter  map[string]string
	Config     Config // decrypted; zero on list/read
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// CreateParams is the input to Create.
type CreateParams struct {
	Type      ChannelType
	Name      string
	Enabled   bool
	Config    Config
	TagFilter map[string]string
}

// UpdateParams is the input to Update. Config is replaced only when
// ReplaceConfig is true (so a PATCH that just toggles Enabled need not
// resend the secret).
type UpdateParams struct {
	Name          string
	Enabled       bool
	TagFilter     map[string]string
	ReplaceConfig bool
	Config        Config
}
