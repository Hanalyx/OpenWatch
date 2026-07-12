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

// deliverEmail sends the alert via SMTP using the channel's configured
// encryption mode (see sendSMTP). Auth is omitted when no username is set.
func deliverEmail(ch Channel, a alertrouter.Alert) error {
	subject := fmt.Sprintf("[OpenWatch] [%s] %s", a.Severity, a.Title)
	msg := buildEmailMessage(ch.Config.From, ch.Config.To, subject, a.Body)
	if err := sendSMTP(ch.Config, ch.Config.From, ch.Config.To, msg); err != nil {
		return fmt.Errorf("notification: email send via %q: %w", ch.Name, err)
	}
	return nil
}

// smtpDialTimeout bounds the TCP connect + TLS handshake for a relay.
const smtpDialTimeout = 10 * time.Second

// sendSMTP delivers a pre-rendered RFC 5322 message to the relay in cfg,
// honoring cfg.SMTPEncryption:
//
//   - "tls":      implicit TLS from connect (SMTPS, typically port 465).
//   - "starttls": connect plaintext, then REQUIRE a STARTTLS upgrade — the
//     send fails rather than silently downgrading to plaintext.
//     This is the default when the mode is empty.
//   - "none":     plaintext, no encryption (a trusted local relay).
//
// PlainAuth is used only when a username is set. The relay host is NOT
// SSRF-restricted (internal relays are legitimate); TLS + auth protect the
// credential. net/smtp.SendMail is deliberately not used: it cannot do
// implicit TLS (465) and only does opportunistic (downgradeable) STARTTLS.
func sendSMTP(cfg Config, from string, to []string, msg []byte) error {
	if len(to) == 0 {
		return fmt.Errorf("smtp: no recipients")
	}
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))
	mode := NormalizeSMTPEncryption(cfg.SMTPEncryption)
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: smtpDialTimeout}

	var conn net.Conn
	var err error
	if mode == SMTPEncTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp: dial %s: %w", addr, err)
	}
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: client: %w", err)
	}
	defer client.Close()

	if mode == SMTPEncSTARTTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp: relay %s does not offer STARTTLS (set encryption to 'none' to allow plaintext)", cfg.SMTPHost)
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	}
	if cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp: mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp: rcpt %s: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: close data: %w", err)
	}
	return client.Quit()
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

// matchesTags decides whether a channel receives an alert. An empty
// filter is a wildcard. The reserved "severity" key uses THRESHOLD
// semantics — the channel receives the alert when its severity is at
// least as high as the filter value (e.g. filter "high" delivers both
// high and critical) — via alertrouter.SeverityOrder (critical=0 is most
// severe). Every other key is an exact match. This is what lets an email
// channel be scoped to "this level and above" rather than one exact level.
func matchesTags(filter, alertTags map[string]string) bool {
	if len(filter) == 0 {
		return true
	}
	for k, v := range filter {
		if k == "severity" {
			ar, aok := alertrouter.SeverityOrder[alertrouter.Severity(alertTags[k])]
			fr, fok := alertrouter.SeverityOrder[alertrouter.Severity(v)]
			if aok && fok {
				if ar > fr { // alert is LESS severe than the threshold
					return false
				}
				continue
			}
		}
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
