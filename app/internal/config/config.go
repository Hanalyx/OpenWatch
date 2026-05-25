// Package config loads OpenWatch runtime configuration.
//
// Layering order (highest precedence first):
//  1. Command-line flags (stdlib flag)
//  2. Environment variables (OPENWATCH_<SECTION>_<KEY>)
//  3. TOML file (--config, default /etc/openwatch/openwatch.toml)
//  4. Built-in defaults (Defaults())
//
// See app/docs/stage_0_walking_skeleton.md Day 2 for the spec; Day 2 ships
// the layering machinery + check-config subcommand. Day 4 wires Server, Day
// 3 wires Database, Day 4 wires Logging.
package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Config is the resolved runtime configuration.
type Config struct {
	Server   ServerConfig   `toml:"server"`
	Database DatabaseConfig `toml:"database"`
	Logging  LoggingConfig  `toml:"logging"`
}

// ServerConfig governs the HTTPS listener.
type ServerConfig struct {
	Listen  string `toml:"listen"`
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
}

// DatabaseConfig governs the PostgreSQL connection.
type DatabaseConfig struct {
	DSN            string `toml:"dsn"`
	MaxConnections int    `toml:"max_connections"`
}

// LoggingConfig governs the structured logger.
type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// Defaults returns the built-in default configuration. Defaults are the
// lowest layer; every other source overrides on top.
func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:  "0.0.0.0:8443",
			TLSCert: "/etc/openwatch/tls/cert.pem",
			TLSKey:  "/etc/openwatch/tls/key.pem",
		},
		Database: DatabaseConfig{
			DSN:            "postgres://openwatch@localhost/openwatch?sslmode=disable",
			MaxConnections: 25,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// DefaultConfigPath is the production config file location.
const DefaultConfigPath = "/etc/openwatch/openwatch.toml"

// Summary returns a human-readable, secret-redacted single-block summary
// of the configuration. Used by `openwatch check-config`.
func (c *Config) Summary() string {
	var b strings.Builder
	b.WriteString("[server]\n")
	fmt.Fprintf(&b, "  listen   = %s\n", c.Server.Listen)
	fmt.Fprintf(&b, "  tls_cert = %s\n", c.Server.TLSCert)
	fmt.Fprintf(&b, "  tls_key  = %s\n", c.Server.TLSKey)
	b.WriteString("\n[database]\n")
	fmt.Fprintf(&b, "  dsn             = %s\n", RedactDSN(c.Database.DSN))
	fmt.Fprintf(&b, "  max_connections = %d\n", c.Database.MaxConnections)
	b.WriteString("\n[logging]\n")
	fmt.Fprintf(&b, "  level  = %s\n", c.Logging.Level)
	fmt.Fprintf(&b, "  format = %s\n", c.Logging.Format)
	return b.String()
}

// RedactDSN strips userinfo's password from a postgres:// URL while keeping
// host, port, db, and query intact. Returns the input unchanged if it can't
// be parsed (which surfaces malformed DSNs to the operator).
//
// Uses string replacement rather than url.UserPassword + u.String() because
// the latter URL-encodes the redacted placeholder ('*' → '%2A'), which is
// noisy in human-facing output.
//
// Exported so cmd/openwatch can render redacted DSNs in its migrate/serve
// output without duplicating the logic.
func RedactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return dsn
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		return dsn
	}
	original := u.User.String() // "user:password" as the URL contained it
	redacted := u.User.Username() + ":***"
	return strings.Replace(dsn, original, redacted, 1)
}
