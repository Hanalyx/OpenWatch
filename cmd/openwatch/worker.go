// cmdWorker entrypoint for the `openwatch worker` subcommand.
//
// Shares boot prerequisites with cmdServe (config, DB pool, audit,
// license, identity, credential DEK) but constructs no HTTP server,
// no event bus, no alert router, no liveness probe. The worker is
// HTTP-free (system-worker-subcommand C-11 / AC-17).
//
// Spec: app/specs/system/worker-subcommand.spec.yaml

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/knownhosts"
	"github.com/Hanalyx/openwatch/internal/license"
	openlog "github.com/Hanalyx/openwatch/internal/log"
	"github.com/Hanalyx/openwatch/internal/scanresult"
	"github.com/Hanalyx/openwatch/internal/scheduler"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/Hanalyx/openwatch/internal/transactionlog"
	"github.com/Hanalyx/openwatch/internal/version"
	"github.com/Hanalyx/openwatch/internal/worker"
)

// cmdWorker runs the scan-job claimer/dispatcher loop. Returns once the
// loop exits cleanly (SIGTERM received and any in-flight job applied)
// or fatally (config / DB / boot prerequisite failure).
//
// Spec: app/specs/system/worker-subcommand.spec.yaml AC-13, AC-16, AC-17.
func cmdWorker(cfg *config.Config, args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pollInterval := fs.Duration("poll-interval", worker.DefaultPollInterval,
		"empty-queue sleep between dequeue attempts (1s default, 5s max)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "openwatch worker: invalid config:\n%v\n", err)
		return 1
	}

	// Same correlation-aware logger as serve.
	logLevel := parseLogLevel(cfg.Logging.Level)
	innerHandler := slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(openlog.NewCorrelationHandler(innerHandler)))

	bootID := correlation.Generate(correlation.PrefixBoot)
	bootCtx := correlation.Set(context.Background(), bootID)

	slog.InfoContext(bootCtx, "openwatch worker starting",
		slog.String("version", version.Version),
		slog.String("commit", version.Commit),
	)

	pool, err := db.NewPool(bootCtx, cfg.Database.DSN, cfg.Database.MaxConnections)
	if err != nil {
		slog.ErrorContext(bootCtx, "failed to open db pool",
			slog.String("dsn", config.RedactDSN(cfg.Database.DSN)),
			slog.String("error", err.Error()))
		return 1
	}
	defer pool.Close()

	// JWT key — required by audit / license-feature-check call paths
	// shared with serve. Same gate as cmdServe.
	if cfg.Identity.JWTPrivateKey == "" {
		slog.ErrorContext(bootCtx, "identity.jwt_private_key is empty")
		return 1
	}
	if err := identity.LoadJWTKey(cfg.Identity.JWTPrivateKey); err != nil {
		slog.ErrorContext(bootCtx, "load jwt key failed",
			slog.String("path", cfg.Identity.JWTPrivateKey),
			slog.String("error", err.Error()))
		return 1
	}

	// Credential DEK — required to decrypt host credentials AND to
	// derive the queue HMAC key (system-worker-subcommand C-11).
	if cfg.Identity.CredentialKeyFile == "" {
		slog.ErrorContext(bootCtx, "identity.credential_key_file is empty")
		return 1
	}
	if err := secretkey.LoadFromFile(cfg.Identity.CredentialKeyFile); err != nil {
		slog.ErrorContext(bootCtx, "load credential key failed",
			slog.String("path", cfg.Identity.CredentialKeyFile),
			slog.String("error", err.Error()))
		return 1
	}

	dekKey, err := secretkey.Active()
	if err != nil {
		slog.ErrorContext(bootCtx, "credential DEK not loaded",
			slog.String("error", err.Error()))
		return 1
	}
	queueKey, err := scheduler.DeriveQueueKey(dekKey.Material())
	if err != nil {
		slog.ErrorContext(bootCtx, "derive queue key failed",
			slog.String("error", err.Error()))
		return 1
	}

	audit.Init(audit.NewStore(pool), audit.DefaultWriterOptions())
	defer audit.Shutdown(5 * time.Second)

	if err := audit.EmitSync(bootCtx, audit.SystemStartup, audit.Event{
		ActorType: "system",
		ActorID:   "openwatch-worker",
		Detail: audit.MakeDetail(map[string]interface{}{
			"version":   version.Version,
			"commit":    version.Commit,
			"component": "worker",
		}),
	}); err != nil {
		slog.WarnContext(bootCtx, "system.startup audit failed",
			slog.String("error", err.Error()))
	}

	if err := license.Init(); err != nil {
		slog.ErrorContext(bootCtx, "license init failed",
			slog.String("error", err.Error()))
		return 1
	}
	licensePath := "/etc/openwatch/license.lic"
	if envPath := os.Getenv("OPENWATCH_LICENSE_FILE"); envPath != "" {
		licensePath = envPath
	}
	if result, err := license.LoadFile(licensePath, license.VerifyOptions{}); err != nil || result != license.VerifyValid {
		if _, statErr := os.Stat(licensePath); statErr == nil {
			slog.WarnContext(bootCtx, "license file rejected",
				slog.String("path", licensePath),
				slog.String("result", string(result)),
			)
		}
	}

	// Wire the scan-job execution chain. The production ScanFunc loads
	// the kensa-rules corpus once and composes the scan-only Kensa over
	// the in-memory transport. Host-key policy matches the discovery
	// transport: TOFU + memory store. Spec system-kensa-executor C-13 /
	// AC-18.
	//
	// Corpus resolution (C-16): production — including air-gapped
	// installs, the primary deployment target — relies on the signed
	// kensa-rules package at the loader's default path
	// (/usr/share/kensa/rules), declared as a dependency of the
	// OpenWatch RPM/DEB. OPENWATCH_KENSA_RULES_DIR is a DEVELOPMENT
	// override only; using it is warned loudly so it cannot creep into
	// a production runbook unnoticed.
	credSvc := credential.NewService(pool)
	bridge := worker.NewCredentialBridge(credSvc)
	rulesDir := os.Getenv("OPENWATCH_KENSA_RULES_DIR")
	if rulesDir != "" {
		slog.WarnContext(bootCtx, "OPENWATCH_KENSA_RULES_DIR override in use — DEVELOPMENT ONLY; production (especially air-gapped) installs the signed kensa-rules package and must not set this",
			slog.String("rules_dir", rulesDir))
	}
	varStore := systemconfig.NewStore(pool, audit.Emit)
	scanFn, err := kensa.NewProductionScanFunc(kensa.ScanFuncDeps{
		Pool:        pool,
		Credentials: credSvc,
		RulesDir:    rulesDir,
		HostKeyMode: owssh.ModeTOFU,
		KnownHosts:  knownhosts.NewStore(pool),
		Variables: func(ctx context.Context) (map[string]string, error) {
			vars, err := varStore.LoadScanVars(ctx)
			return vars, err
		},
		Profiles: connprofile.NewStore(pool),
		Policy: func(ctx context.Context) (bool, error) {
			cfg, err := varStore.LoadSecurity(ctx)
			return cfg.AllowCredentialSudoPassword, err
		},
	})
	if err != nil {
		slog.ErrorContext(bootCtx, "kensa scan wiring failed — is the kensa-rules package installed (or OPENWATCH_KENSA_RULES_DIR set)?",
			slog.String("error", err.Error()))
		return 1
	}
	executor := kensa.NewExecutor(bridge, audit.Emit).WithScanFunc(scanFn)
	writer := transactionlog.NewWriter(pool, audit.Emit)
	scanResultsWriter := scanresult.NewWriter(pool)

	// Post-scan schedule updates run here too: the dedicated worker
	// classifies each completed scan into a compliance state so
	// host_compliance_schedule stays fresh whichever process executed
	// the scan. Ladder snapshot is boot-time config; the serve
	// process's RunManaged tick owns dispatch + live reload.
	// Spec system-scheduler v3.0.0 AC-08.
	scanCfg, scanCfgErr := varStore.LoadScan(bootCtx)
	if scanCfgErr != nil {
		slog.WarnContext(bootCtx, "worker: scan config load failed; schedule updates use defaults",
			slog.String("error", scanCfgErr.Error()))
		scanCfg = systemconfig.DefaultScan()
	}
	sched := scheduler.NewService(pool, scheduler.LoadFromConfig(scanCfg), queueKey, audit.Emit)
	sched.Reload(scheduler.LoadFromConfig(scanCfg), scanCfg.RateLimit,
		!scanCfg.Enabled || scanCfg.MaintenanceGlobal)

	scanWorker := worker.NewScanWorker(worker.Config{
		Pool:         pool,
		Executor:     executor,
		Writer:       writer,
		ScanResults:  scanResultsWriter,
		QueueKey:     queueKey,
		PollInterval: *pollInterval,
		Emit:         audit.Emit,
		Sched:        sched,
	})

	ctx, stop := signal.NotifyContext(bootCtx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.InfoContext(ctx, "openwatch worker ready",
		slog.Duration("poll_interval", *pollInterval),
	)

	runErr := scanWorker.Run(ctx)

	_ = audit.EmitSync(bootCtx, audit.SystemShutdown, audit.Event{
		ActorType: "system",
		ActorID:   "openwatch-worker",
	})

	if runErr != nil {
		slog.ErrorContext(ctx, "worker exited with error",
			slog.String("error", runErr.Error()))
		return 1
	}
	slog.InfoContext(ctx, "openwatch worker shut down cleanly")
	return 0
}
