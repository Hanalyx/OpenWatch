// openwatch is the OpenWatch backend daemon (Go rebuild).
//
// Stage 0 day-by-day:
//
//	Day 1: --version prints build metadata; binary exits cleanly.
//	Day 2 (this): subcommands (serve | migrate | check-config), layered
//	       config (defaults → TOML → env → flags), config validation.
//	Day 3: migrate wires goose.
//	Day 4: serve wires chi + TLS + correlation propagation.
//	Days 5+: audit, RBAC, license, policies, queue.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/Hanalyx/openwatch/internal/license"
	openlog "github.com/Hanalyx/openwatch/internal/log"
	"github.com/Hanalyx/openwatch/internal/server"
	"github.com/Hanalyx/openwatch/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point. main() wraps it.
func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("openwatch", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		configPath  = fs.String("config", config.DefaultConfigPath, "path to TOML config file")
		listen      = fs.String("listen", "", "override [server].listen (host:port)")
		logLevel    = fs.String("log-level", "", "override [logging].level (debug|info|warn|error)")
		showVersion = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() { printUsage(stderr) }

	if err := fs.Parse(args); err != nil {
		// fs already printed the error via SetOutput(stderr).
		return 2
	}

	if *showVersion {
		printVersion(stdout)
		return 0
	}

	// Detect which flags the user explicitly passed (vs. defaults).
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	// Resolve the subcommand. Default is `serve` for systemd compatibility.
	rest := fs.Args()
	subcommand := "serve"
	if len(rest) > 0 {
		subcommand = rest[0]
		rest = rest[1:]
	}

	overrides := &config.FlagOverrides{}
	if explicit["listen"] {
		overrides.Listen = listen
	}
	if explicit["log-level"] {
		overrides.LogLevel = logLevel
	}

	cfg, err := config.Load(config.LoadOptions{
		Path:          *configPath,
		PathRequired:  explicit["config"],
		EnvLookup:     config.OSEnvLookup,
		FlagOverrides: overrides,
	})
	if err != nil {
		fmt.Fprintf(stderr, "openwatch: %v\n", err)
		return 1
	}

	switch subcommand {
	case "serve":
		return cmdServe(cfg, rest, stdout, stderr)
	case "migrate":
		return cmdMigrate(cfg, rest, stdout, stderr)
	case "check-config":
		return cmdCheckConfig(cfg, rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "openwatch: unknown subcommand %q\n\n", subcommand)
		printUsage(stderr)
		return 2
	}
}

// cmdServe runs the HTTPS server. Bootstraps the slog logger with the
// correlation handler, opens the DB pool, inits the audit writer,
// emits system.startup synchronously, and hands off to server.Run.
//
// Spec: app/specs/system/http-server.spec.yaml AC-1.
func cmdServe(cfg *config.Config, _ []string, stdout, stderr *os.File) int {
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "openwatch serve: invalid config:\n%v\n", err)
		return 1
	}

	// Install the correlation-aware JSON logger as the default.
	logLevel := parseLogLevel(cfg.Logging.Level)
	innerHandler := slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(openlog.NewCorrelationHandler(innerHandler)))

	// Boot correlation: every startup event shares one ID.
	bootID := correlation.Generate(correlation.PrefixBoot)
	bootCtx := correlation.Set(context.Background(), bootID)

	slog.InfoContext(bootCtx, "openwatch starting",
		slog.String("version", version.Version),
		slog.String("commit", version.Commit),
		slog.String("listen", cfg.Server.Listen),
	)

	// Open the DB pool. Single pool shared by audit writer, idempotency
	// middleware, and API handlers.
	pool, err := db.NewPool(bootCtx, cfg.Database.DSN, cfg.Database.MaxConnections)
	if err != nil {
		slog.ErrorContext(bootCtx, "failed to open db pool",
			slog.String("dsn", config.RedactDSN(cfg.Database.DSN)),
			slog.String("error", err.Error()))
		return 1
	}
	defer pool.Close()

	// Init audit (writer goroutine starts; package becomes ready to emit).
	audit.Init(audit.NewStore(pool), audit.DefaultWriterOptions())
	defer audit.Shutdown(5 * time.Second)

	// system.startup is critical: must be durable before we accept traffic.
	if err := audit.EmitSync(bootCtx, audit.SystemStartup, audit.Event{
		ActorType: "system",
		ActorID:   "openwatch",
		Detail: audit.MakeDetail(map[string]interface{}{
			"version": version.Version,
			"commit":  version.Commit,
		}),
	}); err != nil {
		slog.WarnContext(bootCtx, "system.startup audit failed", slog.String("error", err.Error()))
		// Non-fatal: server still starts. Operator alerts on the missing event.
	}

	// License: init keyring; load file if present. Missing license file is
	// not fatal — service stays at free tier.
	if err := license.Init(); err != nil {
		slog.ErrorContext(bootCtx, "license init failed", slog.String("error", err.Error()))
		return 1
	}
	licensePath := "/etc/openwatch/license.lic"
	if envPath := os.Getenv("OPENWATCH_LICENSE_FILE"); envPath != "" {
		licensePath = envPath
	}
	if result, err := license.LoadFile(licensePath, license.VerifyOptions{}); err != nil || result != license.VerifyValid {
		// LoadFile returns Valid for missing-file (free tier baseline).
		if _, statErr := os.Stat(licensePath); statErr == nil {
			// File exists but failed validation.
			slog.WarnContext(bootCtx, "license file rejected",
				slog.String("path", licensePath),
				slog.String("result", string(result)),
			)
			license.EmitLoadResult(bootCtx, "boot", result, nil, err)
		}
	} else if state := license.CurrentState(); state != nil && state.License != nil {
		slog.InfoContext(bootCtx, "license loaded",
			slog.String("tier", string(state.License.Tier)),
			slog.String("status", string(state.License.Status)),
			slog.Int("features", len(state.License.Features)),
		)
		license.EmitLoadResult(bootCtx, "boot", license.VerifyValid, state.License, nil)
	} else {
		slog.InfoContext(bootCtx, "no license file; running in free tier",
			slog.String("expected_path", licensePath),
		)
	}

	// Wire shutdown on SIGINT/SIGTERM; SIGHUP triggers license reload.
	ctx, stop := signal.NotifyContext(bootCtx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP: reload license without restart.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	defer signal.Stop(hupCh)
	go func() {
		for range hupCh {
			result, err := license.LoadFile(licensePath, license.VerifyOptions{})
			if err == nil && result == license.VerifyValid {
				if state := license.CurrentState(); state != nil && state.License != nil {
					slog.InfoContext(bootCtx, "license reloaded via SIGHUP",
						slog.String("tier", string(state.License.Tier)),
					)
					license.EmitLoadResult(bootCtx, "sighup", result, state.License, nil)
				} else {
					slog.InfoContext(bootCtx, "license SIGHUP: no file; free tier retained")
				}
			} else {
				slog.WarnContext(bootCtx, "license SIGHUP failed",
					slog.String("result", string(result)),
					slog.String("error", fmt.Sprintf("%v", err)),
				)
				license.EmitLoadResult(bootCtx, "sighup", result, nil, err)
			}
		}
	}()

	srv := server.New(cfg, pool)
	runErr := srv.Run(ctx)

	// system.shutdown: best-effort sync emit; failures logged but ignored
	// because shutdown is in progress.
	_ = audit.EmitSync(bootCtx, audit.SystemShutdown, audit.Event{
		ActorType: "system",
		ActorID:   "openwatch",
	})

	if runErr != nil {
		slog.ErrorContext(ctx, "server exited with error", slog.String("error", runErr.Error()))
		return 1
	}
	slog.InfoContext(ctx, "openwatch shut down cleanly")
	return 0
}

// parseLogLevel maps the config string to a slog.Level. Unknown values
// default to info (Validate would have caught them earlier).
func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// cmdMigrate connects to the configured database, runs goose Up for every
// pending migration, and prints the resulting version.
func cmdMigrate(cfg *config.Config, _ []string, stdout, stderr *os.File) int {
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "openwatch migrate: invalid config:\n%v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := db.NewPool(ctx, cfg.Database.DSN, cfg.Database.MaxConnections)
	if err != nil {
		fmt.Fprintf(stderr, "openwatch migrate: connect %s: %v\n", config.RedactDSN(cfg.Database.DSN), err)
		return 1
	}
	defer pool.Close()

	fmt.Fprintf(stdout, "applying migrations against %s ...\n", config.RedactDSN(cfg.Database.DSN))
	if err := migrations.Apply(ctx, pool); err != nil {
		fmt.Fprintf(stderr, "openwatch migrate: %v\n", err)
		return 1
	}

	version, files, err := migrations.Status(ctx, pool)
	if err != nil {
		fmt.Fprintf(stderr, "openwatch migrate: status: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  current version: %d\n", version)
	fmt.Fprintf(stdout, "  migration files: %d\n", len(files))
	for _, name := range files {
		fmt.Fprintf(stdout, "    - %s\n", name)
	}
	fmt.Fprintln(stdout, "migrations applied")
	return 0
}

// cmdCheckConfig prints the resolved configuration (secrets redacted) and
// runs validation. Exit 0 = valid; exit 1 = invalid.
func cmdCheckConfig(cfg *config.Config, _ []string, stdout, stderr *os.File) int {
	fmt.Fprint(stdout, cfg.Summary())
	fmt.Fprintln(stdout)
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "invalid config:\n%v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "config is valid")
	return 0
}

func printVersion(out *os.File) {
	fmt.Fprintf(out, "openwatch %s\n", version.Version)
	fmt.Fprintf(out, "  commit:    %s\n", version.Commit)
	fmt.Fprintf(out, "  built:     %s\n", version.BuildTime)
	fmt.Fprintf(out, "  fips:      %s\n", version.FIPS)
	fmt.Fprintf(out, "  goversion: %s\n", runtime.Version())
	fmt.Fprintf(out, "  os/arch:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

func printUsage(out *os.File) {
	fmt.Fprintf(out, `openwatch — compliance scanning platform (Go rebuild)

usage:
  openwatch [global flags] <subcommand> [subcommand args]

subcommands:
  serve         run the HTTPS API server (default)        [Day 4]
  migrate       apply pending goose migrations             [Day 3]
  check-config  validate and print resolved config         [Day 2]

global flags:
  --config <path>       TOML config file (default %s)
  --listen <host:port>  override [server].listen
  --log-level <level>   override [logging].level
  --version             print version and exit
  -h, --help            show this help

config layering (highest precedence first):
  CLI flags > env vars (OPENWATCH_<SECTION>_<KEY>) > TOML file > defaults
`, config.DefaultConfigPath)
}
