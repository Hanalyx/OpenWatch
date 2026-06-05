// @spec system-config
//
// AC traceability:
// @ac AC-01  (TestLoad_DefaultsOnly)
// @ac AC-02  (TestLoad_TOMLOverridesDefaults)
// @ac AC-03  (TestLoad_EnvOverridesTOML)
// @ac AC-04  (TestLoad_FlagsOverrideEnv, TestLoad_FullLayering)
// @ac AC-05  (TestLoad_AllEnvVarsApply)
// @ac AC-06  (TestLoad_EnvMaxConnections_InvalidInt)
// @ac AC-07  (TestLoad_MissingTOML_NotRequired_Silent)
// @ac AC-08  (TestLoad_MissingTOML_Required_Errors)
// @ac AC-09  (TestLoad_TOMLMalformed_Errors)
//   (AC-10..AC-15 covered in validate_test.go)

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubEnv returns an EnvLookup backed by a map. Anything not in the map
// returns ("", false), mirroring os.LookupEnv for unset vars.
func stubEnv(env map[string]string) EnvLookup {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

// writeTOML writes content to a temp file and returns its path.
func writeTOML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "openwatch.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp toml: %v", err)
	}
	return path
}

// @ac AC-01  (Load() with zero options returns Defaults().)
func TestLoad_DefaultsOnly(t *testing.T) {
	t.Run("system-config/AC-01", func(t *testing.T) {

		cfg, err := Load(LoadOptions{})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		def := Defaults()
		if cfg.Server.Listen != def.Server.Listen {
			t.Errorf("Server.Listen = %q, want default %q", cfg.Server.Listen, def.Server.Listen)
		}
		if cfg.Database.MaxConnections != def.Database.MaxConnections {
			t.Errorf("Database.MaxConnections = %d, want %d", cfg.Database.MaxConnections, def.Database.MaxConnections)
		}
	})
}

// @ac AC-02  (TOML overwrites set fields; unset fields fall through to defaults.)
func TestLoad_TOMLOverridesDefaults(t *testing.T) {
	t.Run("system-config/AC-02", func(t *testing.T) {

		tomlPath := writeTOML(t, `
	[server]
	listen = "127.0.0.1:9000"

	[logging]
	level = "debug"
	`)

		cfg, err := Load(LoadOptions{Path: tomlPath, PathRequired: true})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Server.Listen != "127.0.0.1:9000" {
			t.Errorf("Server.Listen = %q, want 127.0.0.1:9000", cfg.Server.Listen)
		}
		if cfg.Logging.Level != "debug" {
			t.Errorf("Logging.Level = %q, want debug", cfg.Logging.Level)
		}
		// Unset field falls through to defaults.
		if cfg.Logging.Format != "json" {
			t.Errorf("Logging.Format = %q, want default json", cfg.Logging.Format)
		}
	})
}

// @ac AC-03  (Env vars override TOML for the same field.)
func TestLoad_EnvOverridesTOML(t *testing.T) {
	t.Run("system-config/AC-03", func(t *testing.T) {

		tomlPath := writeTOML(t, `
	[server]
	listen = "127.0.0.1:9000"
	`)

		cfg, err := Load(LoadOptions{
			Path: tomlPath,
			EnvLookup: stubEnv(map[string]string{
				"OPENWATCH_SERVER_LISTEN": "0.0.0.0:7777",
			}),
		})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Server.Listen != "0.0.0.0:7777" {
			t.Errorf("Server.Listen = %q, want 0.0.0.0:7777 (env override)", cfg.Server.Listen)
		}
	})
}

// @ac AC-04  (CLI flags override env (and TOML and defaults).)
func TestLoad_FlagsOverrideEnv(t *testing.T) {
	t.Run("system-config/AC-04", func(t *testing.T) {

		flagListen := "0.0.0.0:1234"
		cfg, err := Load(LoadOptions{
			EnvLookup: stubEnv(map[string]string{
				"OPENWATCH_SERVER_LISTEN": "0.0.0.0:7777",
			}),
			FlagOverrides: &FlagOverrides{Listen: &flagListen},
		})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Server.Listen != "0.0.0.0:1234" {
			t.Errorf("Server.Listen = %q, want 0.0.0.0:1234 (flag override)", cfg.Server.Listen)
		}
	})
}

// @ac AC-04  (Full layering — flags > env > TOML > defaults, with field-level precedence.)
func TestLoad_FullLayering(t *testing.T) {
	t.Run("system-config/AC-04", func(t *testing.T) {

		// defaults < TOML < env < flags
		tomlPath := writeTOML(t, `
	[server]
	listen = "from-toml:1111"
	tls_cert = "/from/toml/cert.pem"

	[logging]
	level = "warn"
	format = "text"
	`)
		envListen := "from-env:2222"
		flagListen := "from-flag:3333"
		flagLogLevel := "error"

		cfg, err := Load(LoadOptions{
			Path: tomlPath,
			EnvLookup: stubEnv(map[string]string{
				"OPENWATCH_SERVER_LISTEN": envListen,
				"OPENWATCH_LOGGING_LEVEL": "debug",
			}),
			FlagOverrides: &FlagOverrides{
				Listen:   &flagListen,
				LogLevel: &flagLogLevel,
			},
		})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		// Flag wins for Listen and LogLevel.
		if cfg.Server.Listen != flagListen {
			t.Errorf("Server.Listen = %q, want %q (flag wins)", cfg.Server.Listen, flagListen)
		}
		if cfg.Logging.Level != flagLogLevel {
			t.Errorf("Logging.Level = %q, want %q (flag wins)", cfg.Logging.Level, flagLogLevel)
		}
		// TOML wins for unset env/flag.
		if cfg.Server.TLSCert != "/from/toml/cert.pem" {
			t.Errorf("Server.TLSCert = %q, want from TOML", cfg.Server.TLSCert)
		}
		if cfg.Logging.Format != "text" {
			t.Errorf("Logging.Format = %q, want text (from TOML)", cfg.Logging.Format)
		}
		// Default wins for fully-unset field.
		if cfg.Database.MaxConnections != Defaults().Database.MaxConnections {
			t.Errorf("Database.MaxConnections = %d, want default", cfg.Database.MaxConnections)
		}
	})
}

// @ac AC-07  (Missing TOML with PathRequired=false silently falls back to defaults.)
func TestLoad_MissingTOML_NotRequired_Silent(t *testing.T) {
	t.Run("system-config/AC-07", func(t *testing.T) {

		cfg, err := Load(LoadOptions{
			Path:         "/does/not/exist.toml",
			PathRequired: false,
		})
		if err != nil {
			t.Fatalf("Load: expected silent fallback, got error: %v", err)
		}
		if cfg.Server.Listen != Defaults().Server.Listen {
			t.Errorf("expected defaults, got Listen=%q", cfg.Server.Listen)
		}
	})
}

// @ac AC-08  (Missing TOML with PathRequired=true errors.)
func TestLoad_MissingTOML_Required_Errors(t *testing.T) {
	t.Run("system-config/AC-08", func(t *testing.T) {

		_, err := Load(LoadOptions{
			Path:         "/does/not/exist.toml",
			PathRequired: true,
		})
		if err == nil {
			t.Fatal("Load: expected error for missing required path, got nil")
		}
	})
}

// @ac AC-06  (Non-integer max_connections env value returns parse error.)
func TestLoad_EnvMaxConnections_InvalidInt(t *testing.T) {
	t.Run("system-config/AC-06", func(t *testing.T) {

		_, err := Load(LoadOptions{
			EnvLookup: stubEnv(map[string]string{
				"OPENWATCH_DATABASE_MAX_CONNECTIONS": "not-a-number",
			}),
		})
		if err == nil {
			t.Fatal("expected error for non-integer OPENWATCH_DATABASE_MAX_CONNECTIONS")
		}
		if !strings.Contains(err.Error(), "MAX_CONNECTIONS") {
			t.Errorf("error does not mention the variable: %v", err)
		}
	})
}

// @ac AC-05  (All seven env vars apply correctly.)
func TestLoad_AllEnvVarsApply(t *testing.T) {
	t.Run("system-config/AC-05", func(t *testing.T) {

		cfg, err := Load(LoadOptions{
			EnvLookup: stubEnv(map[string]string{
				"OPENWATCH_SERVER_LISTEN":            "0.0.0.0:1",
				"OPENWATCH_SERVER_TLS_CERT":          "/c.pem",
				"OPENWATCH_SERVER_TLS_KEY":           "/k.pem",
				"OPENWATCH_DATABASE_DSN":             "postgres://x@y/z",
				"OPENWATCH_DATABASE_MAX_CONNECTIONS": "50",
				"OPENWATCH_LOGGING_LEVEL":            "debug",
				"OPENWATCH_LOGGING_FORMAT":           "text",
			}),
		})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		checks := []struct {
			name string
			got  any
			want any
		}{
			{"Server.Listen", cfg.Server.Listen, "0.0.0.0:1"},
			{"Server.TLSCert", cfg.Server.TLSCert, "/c.pem"},
			{"Server.TLSKey", cfg.Server.TLSKey, "/k.pem"},
			{"Database.DSN", cfg.Database.DSN, "postgres://x@y/z"},
			{"Database.MaxConnections", cfg.Database.MaxConnections, 50},
			{"Logging.Level", cfg.Logging.Level, "debug"},
			{"Logging.Format", cfg.Logging.Format, "text"},
		}
		for _, c := range checks {
			if c.got != c.want {
				t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
			}
		}
	})
}

// @ac AC-09  (Malformed TOML errors regardless of PathRequired.)
func TestLoad_TOMLMalformed_Errors(t *testing.T) {
	t.Run("system-config/AC-09", func(t *testing.T) {

		path := writeTOML(t, "[server\nlisten = oops")
		_, err := Load(LoadOptions{Path: path, PathRequired: true})
		if err == nil {
			t.Fatal("expected error for malformed TOML, got nil")
		}
	})
}
