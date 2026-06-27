package notification

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
	"github.com/Hanalyx/openwatch/internal/httpclient"
	"github.com/google/uuid"
)

// isBlockedHost rejects targets that resolve to non-public space by name
// (literal IPs + obvious loopback names). The dial-time Control guard in
// the delivery client re-checks the post-DNS IP.
func isBlockedHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return isBlockedIP(ip)
	}
	lower := strings.ToLower(host)
	return lower == "localhost" || strings.HasSuffix(lower, ".localhost")
}

// isBlockedIP reports whether ip is in a range an operator-supplied
// webhook must not reach (SSRF). Delegates to the shared guard
// (httpclient.BlockedIP) so the SSRF range list is a single source of truth
// across notifications and the OIDC flow — covers loopback, RFC1918, RFC6598
// CGNAT, link-local (incl. the 169.254.169.254 cloud-metadata endpoint), and
// the unspecified address.
func isBlockedIP(ip net.IP) bool {
	return httpclient.BlockedIP(ip)
}

// ssrfControl runs after DNS resolution with the concrete dial address;
// it blocks the connection if the resolved IP is non-public.
func ssrfControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if ip := net.ParseIP(host); ip != nil && isBlockedIP(ip) {
		return fmt.Errorf("notification: blocked dial to non-public address %s", host)
	}
	return nil
}

// newDeliveryClient builds an HTTP client that refuses to dial non-public
// addresses and pins TLS >= 1.2.
func newDeliveryClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
				Control: ssrfControl,
			}).DialContext,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
	}
}

// renderPayload builds the request body for a channel type. Slack expects
// {"text": ...}; the generic webhook gets the structured alert.
func renderPayload(typ ChannelType, a alertrouter.Alert) ([]byte, error) {
	switch typ {
	case TypeSlack:
		return json.Marshal(map[string]string{
			"text": fmt.Sprintf("[%s] %s\n%s", a.Severity, a.Title, a.Body),
		})
	default: // webhook
		return json.Marshal(map[string]any{
			"id":          a.ID.String(),
			"type":        string(a.Type),
			"severity":    string(a.Severity),
			"title":       a.Title,
			"body":        a.Body,
			"host_id":     a.HostID.String(),
			"rule_id":     a.RuleID,
			"occurred_at": a.OccurredAt.Format(time.RFC3339),
			"tags":        a.Tags,
		})
	}
}

// deliver routes a single alert to one channel: SMTP for email, HTTP POST
// for slack/webhook.
func deliver(ctx context.Context, client *http.Client, ch Channel, a alertrouter.Alert) error {
	if ch.Type == TypeEmail {
		return deliverEmail(ch, a)
	}
	return deliverHTTP(ctx, client, ch, a)
}

// deliverEmail sends the alert via SMTP. smtp.SendMail upgrades to
// STARTTLS when the relay offers it, and PlainAuth refuses to send the
// credential over an unencrypted connection to a non-localhost host — the
// secure default. Auth is omitted when no username is configured.
func deliverEmail(ch Channel, a alertrouter.Alert) error {
	cfg := ch.Config
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)
	}
	subject := fmt.Sprintf("[OpenWatch] [%s] %s", a.Severity, a.Title)
	msg := buildEmailMessage(cfg.From, cfg.To, subject, a.Body)
	if err := smtp.SendMail(addr, auth, cfg.From, cfg.To, msg); err != nil {
		return fmt.Errorf("notification: email send via %q: %w", ch.Name, err)
	}
	return nil
}

// buildEmailMessage assembles a minimal RFC 5322 message.
func buildEmailMessage(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	b.WriteString("\r\n")
	return b.Bytes()
}

// deliverHTTP POSTs the rendered alert to a single channel. A non-2xx
// response is an error. The body is drained + closed so the connection
// can be reused.
func deliverHTTP(ctx context.Context, client *http.Client, ch Channel, a alertrouter.Alert) error {
	body, err := renderPayload(ch.Type, a)
	if err != nil {
		return fmt.Errorf("notification: render payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.Config.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notification: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if ch.Type == TypeWebhook && ch.Config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+ch.Config.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notification: deliver to %q: %w", ch.Name, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification: channel %q returned HTTP %d", ch.Name, resp.StatusCode)
	}
	return nil
}

// matchesTags mirrors alertrouter.ChannelRegistration.matches: an empty
// filter is a wildcard; otherwise every key/value must be present.
func matchesTags(filter, alertTags map[string]string) bool {
	if len(filter) == 0 {
		return true
	}
	for k, v := range filter {
		if alertTags[k] != v {
			return false
		}
	}
	return true
}

// Test delivers a synthetic alert through one channel so an operator can
// confirm wiring. Decrypts the channel secret for this single send.
func (s *Service) Test(ctx context.Context, id uuid.UUID) error {
	ch, err := s.getDecrypted(ctx, id)
	if err != nil {
		return err
	}
	return deliver(ctx, newDeliveryClient(), ch, testAlert())
}

// testAlert is the synthetic alert sent by Test.
func testAlert() alertrouter.Alert {
	return alertrouter.Alert{
		ID:         uuid.Nil,
		Type:       "test",
		Severity:   "info",
		Title:      "OpenWatch test notification",
		Body:       "This is a test from OpenWatch. If you can read this, the channel is wired correctly.",
		OccurredAt: time.Now(),
		Tags:       map[string]string{"test": "true"},
	}
}

// DispatchChannel is the single alertrouter.Channel that fans every fired
// alert out to all enabled, tag-matching notification channels loaded
// from the store. Registering this once means new channels take effect
// without re-registering with the router.
type DispatchChannel struct {
	svc    *Service
	client *http.Client
}

// NewDispatchChannel builds the fan-out channel for alertrouter.Register.
func NewDispatchChannel(svc *Service) *DispatchChannel {
	return &DispatchChannel{svc: svc, client: newDeliveryClient()}
}

// Name satisfies alertrouter.Channel.
func (d *DispatchChannel) Name() string { return "notification-channels" }

// Send loads enabled channels and delivers to those whose tag filter
// matches. A delivery failure to one channel does not stop the others;
// the first error is returned for the router's failure metric.
func (d *DispatchChannel) Send(ctx context.Context, a alertrouter.Alert) error {
	channels, err := d.svc.listEnabledDecrypted(ctx)
	if err != nil {
		return err
	}
	var firstErr error
	for _, ch := range channels {
		if !matchesTags(ch.TagFilter, a.Tags) {
			continue
		}
		if derr := deliver(ctx, d.client, ch, a); derr != nil && firstErr == nil {
			firstErr = derr
		}
	}
	return firstErr
}
