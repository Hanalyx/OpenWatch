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

	"github.com/Hanalyx/openwatch/internal/activity"
	"github.com/Hanalyx/openwatch/internal/alertrouter"
	stdoutchan "github.com/Hanalyx/openwatch/internal/alertrouter/channels/stdout"
	"github.com/Hanalyx/openwatch/internal/alerts"
	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/exception"
	"github.com/Hanalyx/openwatch/internal/group"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/intelligence/collector"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
	discoveryscheduler "github.com/Hanalyx/openwatch/internal/intelligence/discovery/scheduler"
	"github.com/Hanalyx/openwatch/internal/intelligence/scheduler"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/Hanalyx/openwatch/internal/liveness"
	openlog "github.com/Hanalyx/openwatch/internal/log"
	"github.com/Hanalyx/openwatch/internal/posture"
	compsched "github.com/Hanalyx/openwatch/internal/scheduler"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/Hanalyx/openwatch/internal/server"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
	"github.com/Hanalyx/openwatch/internal/sshprivilege"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/Hanalyx/openwatch/internal/transactionlog"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/Hanalyx/openwatch/internal/version"
	"github.com/Hanalyx/openwatch/internal/worker"
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
	case "worker":
		return cmdWorker(cfg, rest, stdout, stderr)
	case "migrate":
		return cmdMigrate(cfg, rest, stdout, stderr)
	case "check-config":
		return cmdCheckConfig(cfg, rest, stdout, stderr)
	case "create-admin":
		return cmdCreateAdmin(cfg, rest, stdout, stderr)
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

	// Load the JWT signing key. Required for /auth/login and refresh-token
	// rotation. There is no silent fallback to ephemeral — a binary with
	// no signing key would 500 every login.
	if cfg.Identity.JWTPrivateKey == "" {
		slog.ErrorContext(bootCtx, "identity.jwt_private_key is empty",
			slog.String("hint", "set [identity].jwt_private_key in the TOML file or OPENWATCH_IDENTITY_JWT_PRIVATE_KEY env"))
		return 1
	}
	if err := identity.LoadJWTKey(cfg.Identity.JWTPrivateKey); err != nil {
		slog.ErrorContext(bootCtx, "load jwt key failed",
			slog.String("path", cfg.Identity.JWTPrivateKey),
			slog.String("error", err.Error()))
		return 1
	}

	// Load the credential DEK. Required for MFA secret encryption and
	// stored SSH credential encryption.
	if cfg.Identity.CredentialKeyFile == "" {
		slog.ErrorContext(bootCtx, "identity.credential_key_file is empty",
			slog.String("hint", "set [identity].credential_key_file in the TOML file or OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE env"))
		return 1
	}
	if err := secretkey.LoadFromFile(cfg.Identity.CredentialKeyFile); err != nil {
		slog.ErrorContext(bootCtx, "load credential key failed",
			slog.String("path", cfg.Identity.CredentialKeyFile),
			slog.String("error", err.Error()))
		return 1
	}

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

	// ---------------------------------------------------------------
	// Slice B wiring. Spec: system-daemon-orchestration.
	//
	// Boot order (C-01, C-09):
	//   1. Pub/sub bus           - Bucket B events
	//   2. Alert router          - subscriber, MUST register and Start
	//                              BEFORE any producer publishes (C-09)
	//   3. Liveness probe loop   - producer: HeartbeatPulse on transitions
	//
	// drift service is constructed elsewhere with no long-lived loop;
	// the worker subcommand calls DetectForScan per-scan-completion
	// in a follow-up PR.
	//
	// OS Intelligence scheduler + on-demand Discovery service land
	// further down (after credSvc + cfgStore are constructed).
	// ---------------------------------------------------------------

	bus := eventbus.NewBus()
	defer bus.Shutdown()

	router, err := alertrouter.NewRouter(bus, alertrouter.Config{})
	if err != nil {
		slog.ErrorContext(bootCtx, "alertrouter init failed", slog.String("error", err.Error()))
		return 1
	}
	// AC-13: register the stdout channel against an empty Tags filter
	// (wildcard — receives every alert). Operators see fired alerts
	// in `journalctl -u openwatch -g alertrouter.alert.sent`.
	router.Register(alertrouter.ChannelRegistration{
		Channel: stdoutchan.New("stdout"),
	})
	router.Start(ctx) // C-09: subscriber active before any publisher.

	// systemconfig store backs operator-tunable runtime values.
	// Connectivity-monitor config (interval, timeout, threshold,
	// maintenance) hot-loads through this. Spec
	// services-connectivity-config.
	cfgStore := systemconfig.NewStore(pool, audit.Emit)

	// v1.3.0 multi-layer adaptive health checks: ICMP ping → SSH
	// banner → sudo. The Pinger picks the best available ICMP
	// strategy at boot (raw with CAP_NET_RAW, else unprivileged via
	// ping_group_range). Both failure modes are logged so operators
	// can confirm — a nil pinger silently falls back to the legacy
	// single-layer SSH-only path. Spec system-liveness-loop C-18.
	pinger, perr := liveness.NewPinger()
	if perr != nil {
		slog.WarnContext(bootCtx, "liveness: ICMP unavailable; falling back to SSH-only probes",
			slog.String("err", perr.Error()))
	} else {
		slog.InfoContext(bootCtx, "liveness: ICMP pinger ready",
			slog.String("mode", string(pinger.Mode())))
		defer func() { _ = pinger.Close() }()
	}

	credSvc := credential.NewService(pool)
	// Spec system-ssh-connectivity v1.2.0 C-09 / AC-18: thread the
	// SecurityConfig reader so the privilege probe can retry sudo -n
	// failures via sudo -S -k with the credential password — same
	// gating as the collector + discovery firewall probe.
	privProbe := sshprivilege.Probe(credSvc, sshprivilege.WithPolicyLoader(cfgStore))

	liveSvc := liveness.NewService(pool, audit.Emit, bus).
		WithConfigLoader(cfgStore.LoadConnectivity).
		WithPinger(pinger).
		WithPrivilegeProbe(privProbe).
		WithMonitoringHistory(true)
	go liveSvc.Run(ctx)

	// OS Discovery service — fingerprints a host via one SSH session,
	// upserts host_system_info + denormalized hosts.os_* columns, and
	// publishes eventbus.HostDiscovered + audit.HostDiscoveryCompleted.
	// Used by POST /hosts/{id}/discovery:run and by the in-process
	// worker that drains host.discovery jobs. Spec system-host-discovery.
	discoSvc := discovery.NewService(pool, audit.Emit, bus).
		WithHostLookup(discovery.PoolHostLookup{Pool: pool}).
		WithCredentialService(credSvc).
		// Spec system-ssh-connectivity v1.2.0 C-09 / AC-20: thread the
		// SecurityConfig reader so the firewall probe can retry a
		// sudo -n failure via sudo -S -k with the credential password
		// — same gating as the collector + the privilege probe.
		WithPolicyLoader(cfgStore)

	// OS Intelligence collector — runs one RunCycle per host: SSH
	// session, snapshot.Collect (packages/services/users/network/etc.),
	// diff against the prior snapshot, persist + emit events. Spec
	// system-os-intelligence.
	//
	// Collector ships only an SSHTransport INTERFACE, no production
	// implementation (the discovery package has the only one in-tree).
	// Reuse the discovery prod transport via a thin adapter — both
	// interfaces have identical method sets, the wrapper just bridges
	// the package-boundary type mismatch on SSHSession.
	collSvc := collector.NewService(pool, audit.Emit, bus).
		WithCredentialService(credSvc).
		WithHostLookup(collector.PoolHostLookup{Pool: pool}).
		WithSSHTransport(collectorSSHAdapter{
			inner: discovery.NewSSHTransport(owssh.ModeTOFU, owssh.NewMemoryStore()),
		}).
		// Spec system-ssh-connectivity v1.1.0 C-09: load the
		// allow_credential_sudo_password knob at cycle start. When the
		// row is missing, LoadSecurity returns DefaultSecurity()
		// (fallback OFF) so existing deployments keep v1.0.0 behavior.
		WithSudoPolicyLoader(func(ctx context.Context) (owssh.SudoPolicy, error) {
			cfg, err := cfgStore.LoadSecurity(ctx)
			return owssh.SudoPolicy{AllowCredentialPassword: cfg.AllowCredentialSudoPassword}, err
		})

	// Intelligence scheduler — cron-like loop that picks "due" hosts
	// from host_intelligence_state.next_intelligence_at and dispatches
	// RunCycle. Interval + RateLimit + maintenance_global come from
	// systemconfig (operator-tunable via PUT /system/intelligence/config).
	// Spec system-intelligence-scheduler.
	intelSched := scheduler.NewService(pool, intelRunner{collector: collSvc}).
		WithConfigLoader(cfgStore.LoadIntelligence)
	go func() { _ = intelSched.Run(ctx) }()

	// Surface MaintenanceGlobal=true at startup. Without this, the
	// scheduler silently skips every tick and the symptom is
	// indistinguishable from "scheduler not running" (no rows in
	// host_intelligence_state, no rows in host_backoff_state, no
	// error logs). Spec system-daemon-orchestration C-08.
	if cfg, err := cfgStore.LoadIntelligence(bootCtx); err == nil && cfg.MaintenanceGlobal {
		slog.WarnContext(bootCtx, "intelligence scheduler paused at startup",
			slog.String("reason", "system_config.intelligence.maintenance_global=true"),
			slog.String("fix", "PUT /api/v1/system/intelligence/config with maintenance_global=false"),
		)
	}

	// Discovery scheduler — sweeps hosts whose hosts.os_discovered_at
	// is NULL or older than DiscoveryConfig.IntervalSec and enqueues
	// host.discovery jobs. Operator-tunable via
	// PUT /system/discovery/config. Spec system-discovery-scheduler.
	discoSched := discoveryscheduler.NewService(pool).
		WithConfigLoader(cfgStore.LoadDiscovery)
	go func() { _ = discoSched.Run(ctx) }()

	if cfg, err := cfgStore.LoadDiscovery(bootCtx); err == nil && cfg.MaintenanceGlobal {
		slog.WarnContext(bootCtx, "discovery scheduler paused at startup",
			slog.String("reason", "system_config.discovery.maintenance_global=true"),
			slog.String("fix", "PUT /api/v1/system/discovery/config with maintenance_global=false"),
		)
	}

	// Scan-job HMAC key — the same DeriveQueueKey(DEK) the worker
	// verifies with, so POST /hosts/{id}/scans enqueues jobs the worker
	// accepts. Spec api-host-scan / system-scan-runs.
	dekKey, err := secretkey.Active()
	if err != nil {
		slog.ErrorContext(bootCtx, "credential DEK not loaded",
			slog.String("error", err.Error()))
		return 1
	}
	scanQueueKey, err := compsched.DeriveQueueKey(dekKey.Material())
	if err != nil {
		slog.ErrorContext(bootCtx, "derive scan queue key failed",
			slog.String("error", err.Error()))
		return 1
	}

	// In-process scan execution: the serve binary processes scan jobs
	// itself (single-binary deployment); a dedicated `openwatch worker`
	// can run alongside for scale-out. When the kensa-rules corpus is
	// missing the executor keeps its fallback binding — scans then
	// terminate failed (kensa_error) instead of rotting queued — and we
	// warn loudly. Spec system-kensa-executor C-13, system-scan-runs.
	//
	// Corpus resolution (C-16): production — including air-gapped
	// installs, the primary deployment target — relies on the signed
	// kensa-rules package at the loader's default path; the env var is
	// a DEVELOPMENT override only, warned loudly when set.
	scanRulesDir := os.Getenv("OPENWATCH_KENSA_RULES_DIR")
	if scanRulesDir != "" {
		slog.WarnContext(bootCtx, "OPENWATCH_KENSA_RULES_DIR override in use — DEVELOPMENT ONLY; production (especially air-gapped) installs the signed kensa-rules package and must not set this",
			slog.String("rules_dir", scanRulesDir))
	}
	// Rule catalog for the failed-rules read path — same corpus
	// resolution as the scan wiring below, constructed once. Non-fatal:
	// without the corpus the endpoint falls back to rule-id titles.
	// Spec api-host-compliance.
	ruleCatalog, catalogErr := kensa.NewRuleCatalog(scanRulesDir)
	if catalogErr != nil {
		slog.WarnContext(bootCtx, "kensa rule catalog unavailable; failed-rules titles fall back to rule ids",
			slog.String("error", catalogErr.Error()))
		ruleCatalog = nil
	}
	// Variable catalog for the Settings scan-variables surface — same
	// corpus resolution, same non-fatal posture (without it the
	// endpoint lists nothing and rejects overrides).
	varCatalog, varCatErr := kensa.NewVariableCatalog(scanRulesDir)
	if varCatErr != nil {
		slog.WarnContext(bootCtx, "kensa variable catalog unavailable; scan-variables surface disabled",
			slog.String("error", varCatErr.Error()))
		varCatalog = nil
	}

	scanExecutor := kensa.NewExecutor(worker.NewCredentialBridge(credSvc), audit.Emit)
	if scanFn, scanErr := kensa.NewProductionScanFunc(kensa.ScanFuncDeps{
		Pool:        pool,
		Credentials: credSvc,
		RulesDir:    scanRulesDir,
		HostKeyMode: owssh.ModeTOFU,
		KnownHosts:  owssh.NewMemoryStore(),
		Variables: func(ctx context.Context) (map[string]string, error) {
			vars, err := cfgStore.LoadScanVars(ctx)
			return vars, err
		},
	}); scanErr != nil {
		slog.WarnContext(bootCtx, "kensa scan wiring unavailable — on-demand scans will fail until the kensa-rules package is installed (or OPENWATCH_KENSA_RULES_DIR set)",
			slog.String("error", scanErr.Error()))
	} else {
		scanExecutor = scanExecutor.WithScanFunc(scanFn)
	}
	// Adaptive compliance scheduler — v3.0.0 ladder from systemconfig
	// (scan plan decision #4). Booted like its siblings (intelSched,
	// discoSched): RunManaged refreshes the config before every 60s
	// tick, so Settings edits apply within a tick and Enabled=false /
	// MaintenanceGlobal=true pause dispatch. Hosts are seeded into
	// host_compliance_schedule by migration 0024 + host create.
	// Spec system-scheduler v3.0.0.
	scanCfg, scanCfgErr := cfgStore.LoadScan(bootCtx)
	if scanCfgErr != nil {
		slog.WarnContext(bootCtx, "scan config load failed at boot; scheduler starts from defaults",
			slog.String("error", scanCfgErr.Error()))
		scanCfg = systemconfig.DefaultScan()
	}
	complianceSched := compsched.NewService(pool, compsched.LoadFromConfig(scanCfg), scanQueueKey, audit.Emit)
	complianceSched.Reload(compsched.LoadFromConfig(scanCfg), scanCfg.RateLimit,
		!scanCfg.Enabled || scanCfg.MaintenanceGlobal)
	complianceSched.RunManaged(ctx, 0, cfgStore)
	if !scanCfg.Enabled || scanCfg.MaintenanceGlobal {
		slog.WarnContext(bootCtx, "compliance scheduler paused at startup",
			slog.Bool("enabled", scanCfg.Enabled),
			slog.Bool("maintenance_global", scanCfg.MaintenanceGlobal))
	}

	// Posture snapshots — hourly per-host rollup powering the 30-day
	// trend card + fleet delta. One pass fires immediately at start so
	// a fresh boot has today's row. Spec system-posture-snapshots.
	posture.Run(ctx, pool, 0)

	// Compliance exception governance + its hourly expiry sweep.
	// Spec api-compliance-exceptions.
	exceptionSvc := exception.NewService(pool, audit.Emit)
	exceptionSvc.Run(ctx, 0)

	scanWorker := worker.NewScanWorker(worker.Config{
		Pool:     pool,
		Executor: scanExecutor,
		Writer:   transactionlog.NewWriter(pool, audit.Emit),
		QueueKey: scanQueueKey,
		Emit:     audit.Emit,
		Bus:      bus,
		Sched:    complianceSched,
	})

	srv := server.New(cfg, pool).
		WithConnectivityConfig(cfgStore, liveSvc).
		WithDiscovery(discoSvc).
		WithEventBus(bus).
		WithActivity(activity.NewService(pool)).
		WithAlerts(alerts.NewService(pool, audit.Emit)).
		WithScanQueue(scanQueueKey).
		WithScanWorker(scanWorker).
		WithRuleCatalog(ruleCatalog).
		WithVariableCatalog(varCatalog).
		WithExceptions(exceptionSvc).
		WithGroups(group.NewService(pool))
	runErr := srv.Run(ctx)

	// Shutdown order REVERSE of boot (C-02). liveness.Run + alertrouter
	// observe ctx cancellation via the same ctx srv.Run watched.
	router.Stop()
	// liveSvc.Run returns when ctx is canceled; no explicit Stop call.

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

// intelRunner adapts collector.Service.RunCycle (which returns
// []collector.Event) into scheduler.RunCycleRunner (which expects
// []any — the scheduler discards the events, it just bumps state on
// success/error). Tiny wrapper rather than changing either side's
// signature.
type intelRunner struct {
	collector *collector.Service
}

func (r intelRunner) RunCycle(ctx context.Context, hostID uuid.UUID) ([]any, error) {
	_, err := r.collector.RunCycle(ctx, hostID)
	return nil, err
}

// collectorSSHAdapter bridges discovery.SSHTransport -> collector.SSHTransport.
// The two packages declare structurally-identical SSHTransport + SSHSession
// interfaces but in their own namespaces, so the same concrete session
// satisfies both. The adapter does the type-narrowing at the
// package boundary.
type collectorSSHAdapter struct {
	inner discovery.SSHTransport
}

func (a collectorSSHAdapter) Dial(ctx context.Context, host string, port int, cred *credential.Credential) (collector.SSHSession, error) {
	sess, err := a.inner.Dial(ctx, host, port, cred)
	if err != nil {
		return nil, err
	}
	return sess, nil
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

// cmdCreateAdmin creates the first admin user from the CLI. Closes the
// chicken-and-egg gap: the API requires an admin to create users, so
// the very first user must be inserted out-of-band. Idempotency:
// re-running with an existing username fails fast — no silent
// promotion of an existing user to admin.
//
// Usage: openwatch create-admin --username NAME --email EMAIL [--password PW]
// If --password is omitted, reads the password from stdin (no echo
// when stdin is a TTY; piped input is accepted for automation).
func cmdCreateAdmin(cfg *config.Config, args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	username := fs.String("username", "", "admin username (required)")
	email := fs.String("email", "", "admin email (required)")
	password := fs.String("password", "", "admin password (read from stdin if omitted)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *username == "" || *email == "" {
		fmt.Fprintln(stderr, "openwatch create-admin: --username and --email are required")
		return 2
	}
	pw := *password
	if pw == "" {
		// Read one line from stdin (no echo handling — operators run
		// this from automation more often than interactively).
		var line string
		_, err := fmt.Fscanln(os.Stdin, &line)
		if err != nil {
			fmt.Fprintf(stderr, "openwatch create-admin: read password from stdin: %v\n", err)
			return 1
		}
		pw = line
	}
	if pw == "" {
		fmt.Fprintln(stderr, "openwatch create-admin: password is empty")
		return 1
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "openwatch create-admin: invalid config:\n%v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := db.NewPool(ctx, cfg.Database.DSN, cfg.Database.MaxConnections)
	if err != nil {
		fmt.Fprintf(stderr, "openwatch create-admin: connect %s: %v\n",
			config.RedactDSN(cfg.Database.DSN), err)
		return 1
	}
	defer pool.Close()

	svc := users.NewService(pool, nil)
	u, err := svc.CreateUser(ctx, users.CreateParams{
		Username:    *username,
		Email:       *email,
		Password:    pw,
		AdminPolicy: true, // CLI bootstraps admins → require 15-char password
	})
	if err != nil {
		fmt.Fprintf(stderr, "openwatch create-admin: %v\n", err)
		return 1
	}
	if err := svc.AssignRole(ctx, u.ID, "admin", nil); err != nil {
		fmt.Fprintf(stderr, "openwatch create-admin: assign admin role: %v\n", err)
		// User was created but role wasn't — surface both states.
		return 1
	}
	fmt.Fprintf(stdout, "created admin user %s (%s) with id=%s\n",
		u.Username, u.Email, u.ID)
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
  serve         run the HTTPS API server (default)
  worker        run the scan-job claimer/dispatcher loop
  migrate       apply pending goose migrations
  create-admin  create the first admin user (requires --username --email --password)
  check-config  validate and print resolved config

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
