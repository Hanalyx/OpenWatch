// @spec system-config
//
// AC traceability:
// @ac AC-10  (TestValidate_DefaultsArePassable)
// @ac AC-11  (TestValidate_Errors)
// @ac AC-12  (TestValidate_AccumulatesErrors)
// @ac AC-13  (TestRedactDSNExported (postgres URL with password))
// @ac AC-14  (TestRedactDSNExported (no password / no userinfo))
// @ac AC-15  (TestRedactDSNExported (unparseable input))

package config

import (
	"strings"
	"testing"
)

// @ac AC-10  (Defaults() passes Validate() with no errors.)
func TestValidate_DefaultsArePassable(t *testing.T) {
	t.Run("system-config/AC-10", func(t *testing.T) {

		// Sanity: out-of-the-box defaults pass validation. If they don't,
		// every fresh `openwatch check-config` against just defaults fails.
		if err := Defaults().Validate(); err != nil {
			t.Fatalf("Defaults() failed Validate: %v", err)
		}
	})
}

// @ac AC-11  (Validate() rejects each invalid-field case with a specific error.)
func TestValidate_Errors(t *testing.T) {
	t.Run("system-config/AC-11", func(t *testing.T) {

		cases := []struct {
			name   string
			mutate func(c *Config)
			want   string // substring that should appear in the error
		}{
			{"empty listen", func(c *Config) { c.Server.Listen = "" }, "server.listen"},
			{"malformed listen", func(c *Config) { c.Server.Listen = "no-port" }, "server.listen"},
			{"empty tls cert", func(c *Config) { c.Server.TLSCert = "" }, "server.tls_cert"},
			{"empty tls key", func(c *Config) { c.Server.TLSKey = "" }, "server.tls_key"},
			{"empty dsn", func(c *Config) { c.Database.DSN = "" }, "database.dsn"},
			{"wrong scheme", func(c *Config) { c.Database.DSN = "mysql://x@y/z" }, "postgres"},
			{"zero max_connections", func(c *Config) { c.Database.MaxConnections = 0 }, "max_connections"},
			{"negative max_connections", func(c *Config) { c.Database.MaxConnections = -1 }, "max_connections"},
			{"unknown level", func(c *Config) { c.Logging.Level = "trace" }, "logging.level"},
			{"unknown format", func(c *Config) { c.Logging.Format = "xml" }, "logging.format"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cfg := Defaults()
				tc.mutate(cfg)
				err := cfg.Validate()
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error %q does not contain expected substring %q", err, tc.want)
				}
			})
		}
	})
}

// @ac AC-12  (Validate() accumulates and reports all errors.)
func TestValidate_AccumulatesErrors(t *testing.T) {
	t.Run("system-config/AC-12", func(t *testing.T) {

		cfg := Defaults()
		cfg.Server.Listen = ""
		cfg.Database.MaxConnections = 0
		cfg.Logging.Level = "verbose"

		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected combined errors, got nil")
		}
		for _, want := range []string{"server.listen", "max_connections", "logging.level"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("combined error missing %q: %v", want, err)
			}
		}
	})
}

// @ac AC-13  (RedactDSN redacts the password component to "***" while)
// preserving scheme/user/host/path.
func TestRedactDSNExported(t *testing.T) {
	t.Run("system-config/AC-13", func(t *testing.T) {
		got := RedactDSN("postgres://user:secret@host:5432/db")
		if got != "postgres://user:***@host:5432/db" {
			t.Errorf("RedactDSN = %q", got)
		}
	})
}

// @ac AC-14  (RedactDSN preserves DSNs with no password unchanged.)
func TestRedactDSN_NoPasswordUnchanged(t *testing.T) {
	t.Run("system-config/AC-14", func(t *testing.T) {
		cases := []string{
			"postgres://user@host/db",
			"postgres://host/db",
		}
		for _, in := range cases {
			if got := RedactDSN(in); got != in {
				t.Errorf("RedactDSN(%q) = %q, want unchanged", in, got)
			}
		}
	})
}

// @ac AC-15  (RedactDSN returns input unchanged when not parseable as URL.)
func TestRedactDSN_UnparseableUnchanged(t *testing.T) {
	t.Run("system-config/AC-15", func(t *testing.T) {
		in := "not a url"
		if got := RedactDSN(in); got != in {
			t.Errorf("RedactDSN(%q) = %q, want unchanged", in, got)
		}
	})
}
