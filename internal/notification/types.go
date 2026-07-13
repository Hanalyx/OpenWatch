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
	TypeEmail   ChannelType = "email"
)

// IsValid reports whether t is a supported channel type.
func (t ChannelType) IsValid() bool {
	return t == TypeSlack || t == TypeWebhook || t == TypeEmail
}

// IsHTTP reports whether the channel delivers over HTTP (slack/webhook),
// as opposed to SMTP (email).
func (t ChannelType) IsHTTP() bool {
	return t == TypeSlack || t == TypeWebhook
}

// Config is the decrypted, in-process-only secret payload for a channel.
// It is never serialized to the API or logged. The URL/Token fields apply
// to HTTP channels (slack/webhook); the SMTP* + mail fields apply to email.
type Config struct {
	// URL is the Slack incoming-webhook URL or the generic webhook
	// endpoint. Must be https to a public host (SSRF guard).
	URL string `json:"url,omitempty"`
	// Token, when set (webhook only), is sent as an Authorization:
	// Bearer header. Optional.
	Token string `json:"token,omitempty"`

	// Email/SMTP fields (TypeEmail). The relay may be an internal host —
	// SMTP is operator-trusted infrastructure, so the public-host SSRF
	// block that applies to webhook/slack is NOT applied here; TLS
	// (STARTTLS) + auth still protect the credential.
	SMTPHost string   `json:"smtp_host,omitempty"`
	SMTPPort int      `json:"smtp_port,omitempty"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	// SMTPEncryption selects the transport security for the SMTP
	// connection: "none" (plaintext, for a trusted local relay),
	// "starttls" (connect plaintext then require a STARTTLS upgrade), or
	// "tls" (implicit TLS from connect — SMTPS, typically port 465). An
	// empty value is treated as "starttls" (the secure default). Not a
	// secret; returned to the edit form.
	SMTPEncryption string `json:"smtp_encryption,omitempty"`
	// SMTPInsecureSkipVerify, when true, disables TLS certificate
	// verification for the STARTTLS/implicit-TLS handshake. It exists ONLY
	// for an internal relay (e.g. a local postfix) that presents a
	// self-signed or private-CA certificate; it is a MITM-exposing downgrade
	// and has no effect when encryption is "none". Not a secret; returned to
	// the edit form.
	SMTPInsecureSkipVerify bool `json:"smtp_insecure_skip_verify,omitempty"`
}

// SMTP encryption modes for Config.SMTPEncryption.
const (
	SMTPEncNone     = "none"
	SMTPEncSTARTTLS = "starttls"
	SMTPEncTLS      = "tls"
)

// NormalizeSMTPEncryption maps an empty/unknown mode to the secure
// default (STARTTLS, required). Callers persist and act on the result so
// legacy rows (no mode) behave predictably.
func NormalizeSMTPEncryption(mode string) string {
	switch mode {
	case SMTPEncNone, SMTPEncTLS:
		return mode
	default:
		return SMTPEncSTARTTLS
	}
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
