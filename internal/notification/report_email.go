package notification

// Report email delivery: a MIME-multipart email carrying a rendered report
// PDF as an attachment, sent through an existing EMAIL channel's SMTP
// config to that channel's configured recipients. The scheduled-report
// dispatcher (internal/reportschedule) uses this; the alert path
// (delivery.go) stays plain-text. Only email channels can carry an
// attachment, so a non-email channel is rejected.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// ErrNotEmailChannel is returned when a report email is requested for a
// non-email channel (only email channels carry attachments).
var ErrNotEmailChannel = errors.New("notification: channel is not an email channel")

// SendReportEmail delivers a report PDF as a MIME-multipart attachment
// through the email channel's SMTP config, to the channel's recipients.
func (s *Service) SendReportEmail(ctx context.Context, channelID uuid.UUID, subject, body, filename string, attachment []byte) error {
	ch, err := s.getDecrypted(ctx, channelID)
	if err != nil {
		return err
	}
	if ch.Type != TypeEmail {
		return ErrNotEmailChannel
	}
	cfg := ch.Config
	if len(cfg.To) == 0 {
		return fmt.Errorf("notification: email channel %q has no recipients", ch.Name)
	}
	msg := buildReportEmail(cfg.From, cfg.To, subject, body, filename, attachment)
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)
	}
	if err := smtp.SendMail(addr, auth, cfg.From, cfg.To, msg); err != nil {
		return fmt.Errorf("notification: report email via %q: %w", ch.Name, err)
	}
	return nil
}

// buildReportEmail assembles a multipart/mixed RFC 5322 message: a
// text/plain body part and a base64-encoded application/pdf attachment.
func buildReportEmail(from string, to []string, subject, body, filename string, attachment []byte) []byte {
	// Defense-in-depth: strip CR/LF from the subject so a value flowing into
	// the Subject header can never inject additional headers (CWE-93). Report
	// titles are fixed today, but this future-proofs the header.
	subject = stripCRLF(subject)
	filename = stripCRLF(filename)
	var parts bytes.Buffer
	w := multipart.NewWriter(&parts)

	textHdr := textproto.MIMEHeader{}
	textHdr.Set("Content-Type", "text/plain; charset=utf-8")
	if tw, err := w.CreatePart(textHdr); err == nil {
		_, _ = tw.Write([]byte(body))
	}

	attHdr := textproto.MIMEHeader{}
	attHdr.Set("Content-Type", "application/pdf")
	attHdr.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	attHdr.Set("Content-Transfer-Encoding", "base64")
	if aw, err := w.CreatePart(attHdr); err == nil {
		_, _ = aw.Write([]byte(wrap76(base64.StdEncoding.EncodeToString(attachment))))
	}
	_ = w.Close()

	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", from)
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	msg.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "Content-Type: multipart/mixed; boundary=%s\r\n", w.Boundary())
	msg.WriteString("\r\n")
	msg.Write(parts.Bytes())
	return msg.Bytes()
}

// stripCRLF removes carriage returns and newlines so a value cannot inject
// extra MIME/RFC-5322 headers.
func stripCRLF(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// wrap76 breaks a base64 string into 76-character CRLF-terminated lines
// (RFC 2045).
func wrap76(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76])
		b.WriteString("\r\n")
		s = s[76:]
	}
	b.WriteString(s)
	b.WriteString("\r\n")
	return b.String()
}
