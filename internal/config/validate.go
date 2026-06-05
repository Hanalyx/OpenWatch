package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Validate checks the resolved Config for semantic correctness. Returns nil
// when the config is acceptable; otherwise returns a single error joining all
// failures so `openwatch check-config` can print every problem at once.
//
// File-existence checks (does tls_cert exist? is dsn reachable?) are NOT done
// here — Validate is fast and side-effect-free. Existence/reachability is
// Day 3 (DB) and Day 4 (TLS) territory.
func (c *Config) Validate() error {
	var errs []error

	// --- server ----------------------------------------------------------
	if c.Server.Listen == "" {
		errs = append(errs, errors.New("server.listen: must not be empty"))
	} else if _, _, err := net.SplitHostPort(c.Server.Listen); err != nil {
		errs = append(errs, fmt.Errorf("server.listen: %q is not host:port: %w", c.Server.Listen, err))
	}
	if c.Server.TLSCert == "" {
		errs = append(errs, errors.New("server.tls_cert: must not be empty"))
	}
	if c.Server.TLSKey == "" {
		errs = append(errs, errors.New("server.tls_key: must not be empty"))
	}

	// --- database --------------------------------------------------------
	if c.Database.DSN == "" {
		errs = append(errs, errors.New("database.dsn: must not be empty"))
	} else if u, err := url.Parse(c.Database.DSN); err != nil {
		errs = append(errs, fmt.Errorf("database.dsn: %w", err))
	} else if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		errs = append(errs, fmt.Errorf("database.dsn: scheme %q must be postgres:// or postgresql://", u.Scheme))
	}
	if c.Database.MaxConnections <= 0 {
		errs = append(errs, fmt.Errorf("database.max_connections: must be > 0, got %d", c.Database.MaxConnections))
	}

	// --- logging ---------------------------------------------------------
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
		// ok
	default:
		errs = append(errs, fmt.Errorf("logging.level: %q must be debug | info | warn | error", c.Logging.Level))
	}
	switch c.Logging.Format {
	case "json", "text":
		// ok
	default:
		errs = append(errs, fmt.Errorf("logging.format: %q must be json | text", c.Logging.Format))
	}

	if len(errs) == 0 {
		return nil
	}
	return joinErrors(errs)
}

// joinErrors composes a single error from a slice. We do this manually
// (rather than errors.Join) so the output is human-friendly for check-config:
// one error per line, no nested "Unwrap: ..." noise.
func joinErrors(errs []error) error {
	var b strings.Builder
	for i, e := range errs {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "  - %s", e)
	}
	return errors.New(b.String())
}
