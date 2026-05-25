package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
)

// EnvLookup matches os.LookupEnv's signature. Tests pass a stub.
type EnvLookup func(key string) (value string, ok bool)

// FlagOverrides holds the CLI-flag values that may override the config.
// nil fields mean "no override at this layer".
//
// Add a new flag: add a pointer field here, set it in main.go after flag.Parse(),
// and read it in applyFlags below.
type FlagOverrides struct {
	Listen   *string // --listen
	LogLevel *string // --log-level
}

// LoadOptions controls the Load call. See package doc for layering order.
type LoadOptions struct {
	// Path is the TOML file path. Empty means skip the TOML layer entirely.
	Path string

	// PathRequired causes Load to fail if Path is non-empty but the file
	// is missing. When false, a missing file is silent (defaults stand).
	// Callers set this true when the user passed --config explicitly.
	PathRequired bool

	// EnvLookup is the env-var lookup function. nil means skip the env layer.
	// Production callers pass os.LookupEnv.
	EnvLookup EnvLookup

	// FlagOverrides holds CLI-flag overrides. nil means skip the flag layer.
	FlagOverrides *FlagOverrides
}

// Load resolves the layered configuration in precedence order:
//
//	defaults < TOML file < env vars < CLI flags
//
// Returns the resolved Config or an error if any layer was malformed. Caller
// should then run cfg.Validate() to check semantic correctness.
func Load(opts LoadOptions) (*Config, error) {
	cfg := Defaults()

	if opts.Path != "" {
		if err := applyTOMLFile(cfg, opts.Path); err != nil {
			if errors.Is(err, fs.ErrNotExist) && !opts.PathRequired {
				// Silent fallback: user took the default path and the file
				// isn't there. Defaults remain in cfg.
			} else {
				return nil, fmt.Errorf("config: load %s: %w", opts.Path, err)
			}
		}
	}

	if opts.EnvLookup != nil {
		if err := applyEnv(cfg, opts.EnvLookup); err != nil {
			return nil, fmt.Errorf("config: env override: %w", err)
		}
	}

	if opts.FlagOverrides != nil {
		applyFlags(cfg, opts.FlagOverrides)
	}

	return cfg, nil
}

// applyTOMLFile decodes a TOML file into cfg, overwriting only fields the
// file specifies (BurntSushi/toml leaves unset fields alone).
func applyTOMLFile(cfg *Config, path string) error {
	_, err := toml.DecodeFile(path, cfg)
	return err
}

// envOverride is one row in the env-var → config-field map.
type envOverride struct {
	key   string
	apply func(c *Config, value string) error
}

// envOverrides enumerates every supported OPENWATCH_* variable. Adding a new
// override is a one-liner here; reflection is avoided so the audit surface
// stays explicit.
var envOverrides = []envOverride{
	{"OPENWATCH_SERVER_LISTEN", func(c *Config, v string) error { c.Server.Listen = v; return nil }},
	{"OPENWATCH_SERVER_TLS_CERT", func(c *Config, v string) error { c.Server.TLSCert = v; return nil }},
	{"OPENWATCH_SERVER_TLS_KEY", func(c *Config, v string) error { c.Server.TLSKey = v; return nil }},

	{"OPENWATCH_DATABASE_DSN", func(c *Config, v string) error { c.Database.DSN = v; return nil }},
	{"OPENWATCH_DATABASE_MAX_CONNECTIONS", func(c *Config, v string) error {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("OPENWATCH_DATABASE_MAX_CONNECTIONS: %w", err)
		}
		c.Database.MaxConnections = n
		return nil
	}},

	{"OPENWATCH_LOGGING_LEVEL", func(c *Config, v string) error { c.Logging.Level = v; return nil }},
	{"OPENWATCH_LOGGING_FORMAT", func(c *Config, v string) error { c.Logging.Format = v; return nil }},
}

// applyEnv consults each registered env-var; the lookup returns ok=false for
// unset vars (no override applied).
func applyEnv(cfg *Config, lookup EnvLookup) error {
	for _, ov := range envOverrides {
		val, ok := lookup(ov.key)
		if !ok {
			continue
		}
		if err := ov.apply(cfg, val); err != nil {
			return err
		}
	}
	return nil
}

// applyFlags applies non-nil CLI-flag overrides. nil pointer = no override.
func applyFlags(cfg *Config, f *FlagOverrides) {
	if f.Listen != nil {
		cfg.Server.Listen = *f.Listen
	}
	if f.LogLevel != nil {
		cfg.Logging.Level = *f.LogLevel
	}
}

// OSEnvLookup is the production EnvLookup; calls os.LookupEnv.
var OSEnvLookup EnvLookup = os.LookupEnv
