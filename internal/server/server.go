// Package server runs the OpenWatch HTTPS API server.
//
// Day 4 ships: chi router with correlation middleware, TLS hot-reload via
// GetCertificate, locked http.Server timeouts. Day 5+ register real
// endpoints onto the router exposed via the Routes accessor.
//
// Spec: app/specs/system/http-server.spec.yaml.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Hanalyx/openwatch/internal/apitoken"
	"github.com/Hanalyx/openwatch/internal/authpolicy"
	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/exception"
	"github.com/Hanalyx/openwatch/internal/group"
	"github.com/Hanalyx/openwatch/internal/idempotency"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/Hanalyx/openwatch/internal/notification"
	"github.com/Hanalyx/openwatch/internal/remediation"
	"github.com/Hanalyx/openwatch/internal/report"
	"github.com/Hanalyx/openwatch/internal/scanresult"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/sso"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/Hanalyx/openwatch/internal/worker"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/activity"
	"github.com/Hanalyx/openwatch/internal/alerts"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
	"github.com/Hanalyx/openwatch/internal/liveness"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// Server holds the running HTTP server state. Build via New; start with Run.
type Server struct {
	cfg      *config.Config
	router   chi.Router
	srv      *http.Server
	cm       *certManager
	wkr      *worker.Worker
	handlers *handlers
}

// WithConnectivityConfig threads the systemconfig store + live
// liveness Service into the API handlers so the /system/connectivity/*
// endpoints can read/write config and the on-demand
// /hosts/{id}/connectivity:check endpoint can trigger probes.
// Spec api-system-connectivity, api-host-connectivity-check.
func (s *Server) WithConnectivityConfig(store *systemconfig.Store, live *liveness.Service) *Server {
	s.handlers.sysCfg = store
	s.handlers.liveSvc = live
	return s
}

// WithEventBus threads the in-process pub/sub bus into the handlers so
// the SSE endpoint can subscribe and fan events out to operator
// browsers. Spec api-events-stream (Track B).
func (s *Server) WithEventBus(bus *eventbus.Bus) *Server {
	s.handlers.bus = bus
	// Mount the SSE route directly on the chi router so we keep
	// long-lived streams off the oapi-codegen path (which assumes
	// short-lived JSON RPC-style responses). The route is auth-gated
	// via a query-string token because browsers' EventSource cannot
	// send custom headers.
	s.router.Get("/api/v1/events", s.handlers.GetEventsStream)
	return s
}

// WithDiscovery threads the OS Discovery service into the API handlers
// AND the in-process worker so /hosts/{id}/discovery:run can trigger a
// one-shot fingerprint and the worker can drain host.discovery jobs.
// Spec system-host-discovery.
func (s *Server) WithDiscovery(d *discovery.Service) *Server {
	s.handlers.discoSvc = d
	if s.wkr != nil {
		s.wkr.WithDiscovery(d)
	}
	return s
}

// WithAlerts threads the alert lifecycle service into the API handlers
// so /api/v1/alerts and the :verb endpoints are routable.
// Spec system-alerts + api-alerts.
func (s *Server) WithAlerts(a *alerts.Service) *Server {
	s.handlers.alertsSvc = a
	return s
}

// WithActivity threads the unified Activity feed service into the API
// handlers so /api/v1/activity is routable. Spec api-activity.
func (s *Server) WithActivity(a *activity.Service) *Server {
	s.handlers.activitySvc = a
	return s
}

// WithScanQueue threads the scan-job HMAC key into the API handlers so
// POST /hosts/{id}/scans can sign and enqueue jobs the worker accepts.
// Spec api-host-scan.
func (s *Server) WithScanQueue(queueKey []byte) *Server {
	s.handlers.scanQueueKey = queueKey
	return s
}

// WithRuleCatalog threads the in-memory kensa rule catalog into the
// API handlers so /hosts/{id}/compliance/failed-rules can resolve rule
// titles and categories. Nil-safe: without a catalog the endpoint
// falls back to rule ids. Spec api-host-compliance.
func (s *Server) WithRuleCatalog(c *kensa.RuleCatalog) *Server {
	s.handlers.ruleCatalog = c
	return s
}

// WithRuleLibrary threads the normalized kensa rule library into the API
// handlers so /api/v1/rules is routable. Nil makes that endpoint 503.
// Spec api-rules.
func (s *Server) WithRuleLibrary(l *kensa.RuleLibrary) *Server {
	s.handlers.ruleLibrary = l
	return s
}

// WithExceptions threads the compliance exception governance service
// into the API handlers. Nil makes the exception endpoints 503.
// Spec api-compliance-exceptions.
func (s *Server) WithExceptions(e *exception.Service) *Server {
	s.handlers.exceptionSvc = e
	return s
}

// WithRemediation threads the remediation governance service (free core)
// into the API handlers. Nil makes the remediation endpoints 503.
// Spec api-remediation.
func (s *Server) WithRemediation(rm *remediation.Service) *Server {
	s.handlers.remediationSvc = rm
	return s
}

// WithGroups threads the host group service (sites + OS categories)
// into the API handlers so /api/v1/groups and its sub-routes are
// routable. Nil makes the group endpoints 503. Spec api-groups.
func (s *Server) WithGroups(g *group.Service) *Server {
	s.handlers.groupSvc = g
	return s
}

// WithReports threads the reports library service into the API handlers
// so /api/v1/reports and its sub-routes are routable. Nil makes the
// report endpoints 503. Spec api-reports.
func (s *Server) WithReports(rep *report.Service) *Server {
	s.handlers.reportSvc = rep
	return s
}

// WithScanResults threads the durable per-scan results reader into the
// API handlers so /api/v1/scans and its sub-routes are routable. Nil
// makes the scan endpoints 503. Spec api-scans.
func (s *Server) WithScanResults(rd *scanresult.Reader) *Server {
	s.handlers.scanResultSvc = rd
	return s
}

// WithNotifications threads the notification-channel service into the API
// handlers so /api/v1/notifications/channels is routable. Nil makes the
// notification endpoints 503. Spec api-notifications.
func (s *Server) WithNotifications(svc *notification.Service) *Server {
	s.handlers.notificationSvc = svc
	return s
}

// WithVariableCatalog threads the kensa variable catalog into the API
// handlers so /system/scan/variables can list corpus-used variables
// and validate override names. Nil-safe. Spec api-system-scan-config.
func (s *Server) WithVariableCatalog(c *kensa.VariableCatalog) *Server {
	s.handlers.varCatalog = c
	return s
}

// WithScanWorker registers the scan processor on the in-process job
// worker, so "scan" jobs claimed by the serve process execute instead
// of dead-ending (queue.Dequeue is not type-filtered). Spec
// api-host-scan / system-scan-runs.
func (s *Server) WithScanWorker(sw *worker.ScanWorker) *Server {
	if s.wkr != nil {
		s.wkr.WithScanProcessor(sw)
	}
	return s
}

// WithRemediationWorker registers the remediation processor on the in-process
// job worker, so "remediation" jobs claimed by the serve process execute
// instead of dead-ending. Spec api-remediation.
func (s *Server) WithRemediationWorker(rw *worker.RemediationWorker) *Server {
	if s.wkr != nil {
		s.wkr.WithRemediationProcessor(rw)
	}
	return s
}

// New constructs a Server from validated config and DB pool. The returned
// Server has the foundation middleware chain mounted (correlation first,
// then idempotency) and the Stage-0 API routes generated from
// app/api/openapi.yaml registered.
func New(cfg *config.Config, pool *pgxpool.Pool) *Server {
	r := chi.NewRouter()

	// FIRST middleware in the chain — every other layer (audit, logging,
	// auth, idempotency) depends on correlation_id being on context.
	r.Use(correlation.HTTPMiddleware)

	// Security response headers (HSTS, CSP, nosniff, frame-deny,
	// referrer-policy) on every response — the single binary serves the SPA
	// + API from one origin, so this is the hardening an edge proxy would
	// otherwise add. Spec system-http-server C-12.
	r.Use(securityHeaders)

	// Throttle the authentication endpoints (login + MFA verify) per client
	// IP against online password/OTP guessing. Per-server-instance so it is
	// isolated across tests. Spec system-http-server C-13.
	r.Use(rateLimitAuth(newRateLimiter(authRateLimitPerMinute, time.Minute)))

	// Double-submit CSRF protection on unsafe, cookie-authenticated requests.
	// Spec system-http-server C-14.
	r.Use(csrfProtect)

	// Identity binder. Reads session cookie or Bearer JWT, translates to
	// auth.Identity via the users.Service Lookups adapter. Sets a
	// non-anonymous Identity on success (anonymous if not). Does NOT
	// reject on its own — that's the handler's job via EnforcePermission.
	// Per app/specs/system/auth-identity.spec.yaml AC-17.
	usrSvc := users.NewService(pool, identity.DefaultBreachCorpus())
	// API service-account tokens (owk_) authenticate on the bearer path
	// via the token service; the same instance backs the /tokens handlers.
	apiTokenSvc := apitoken.NewService(pool)
	r.Use(identity.Binder(pool, usrSvc, identity.WithTokenAuth(apiTokenSvc)))

	// Idempotency middleware: short-circuits replays of mutating requests
	// that include an Idempotency-Key header. No-op for GET/HEAD/OPTIONS.
	// Per app/specs/system/idempotency.spec.yaml.
	r.Use(idempotency.Middleware(pool))

	// chi's default NotFound/MethodNotAllowed handlers short-circuit
	// AROUND the middleware chain. Register explicit handlers so responses
	// also carry X-Correlation-Id.
	//
	// NotFound serves the embedded single-page app: API routes registered
	// below match first, so only non-API paths (/, /hosts, /assets/*, deep
	// links) fall through here. The handler returns a JSON-less 404 for
	// unmatched /api/ paths and the SPA (static asset or index.html
	// fallback) for everything else.
	r.NotFound(newSPAHandler().ServeHTTP)
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
	})

	// Mount the Stage-0 API routes via oapi-codegen's HandlerFromMux.
	// HandlerFromMux wires every operationId in openapi.yaml to the
	// matching method on our ServerInterface implementation.
	//
	// License gating for premium endpoints is enforced inside the handler
	// (PostDiagnosticsPremiumEcho calls license.IsEnabled at the top).
	// Spec-AC equivalence: the 402 envelope + audit emit happen via
	// license.DenyFeature regardless of where the check is.
	apiHandlers := newHandlers(pool)
	// The token service is always available (it only wraps the pool), so
	// wire it directly rather than via an optional WithX setter.
	apiHandlers.apiTokenSvc = apiTokenSvc
	// The auth-policy service is likewise always available. Prime the
	// identity session windows from the stored policy so sessions honour
	// it from the first request. Best-effort: a missing policy row (e.g.
	// a test pool without the 0033 migration) leaves the identity defaults
	// in place, which are behaviour-preserving.
	apiHandlers.authPolicySvc = authpolicy.NewService(pool)
	// SSO (OIDC) is always available; it wraps the pool + the mandated
	// outbound client. The endpoints 503 only the rare config-less paths.
	apiHandlers.ssoSvc = sso.NewService(pool)
	// Guard on a non-nil pool: a few unit tests construct New(cfg, nil) to
	// assert wiring that doesn't touch the DB. The identity defaults remain
	// in place when priming is skipped.
	if pool != nil {
		primeCtx, primeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := apiHandlers.authPolicySvc.Prime(primeCtx); err != nil {
			slog.WarnContext(primeCtx, "auth policy prime skipped; using default session windows", "error", err)
		}
		primeCancel()
	}
	api.HandlerFromMux(apiHandlers, r)
	_ = license.PremiumDiagnostics // ensure import is exercised

	// OpenAPI spec + Swagger UI. The handlers do not call
	// EnforcePermission, so they remain reachable for anonymous
	// callers — reviewers in air-gapped environments can browse the
	// docs without first bootstrapping an admin.
	// Spec: app/specs/api/openapi-docs.spec.yaml.
	mountOpenAPIDocs(r)

	cm := newCertManager(cfg.Server.TLSCert, cfg.Server.TLSKey)

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KiB
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: cm.getCertificate,
		},
	}

	// In-process worker that drains the job queue (diagnostics, discovery,
	// and — via WithScanProcessor — scans). Started by Run, stopped on
	// shutdown. ScanConcurrency fans it out so a fleet of queued scans does
	// not drain one host at a time (system-job-queue C-07). Spec
	// release-stage-0-signoff AC-10.
	var wkr *worker.Worker
	if pool != nil {
		wkr = worker.New(pool).WithConcurrency(cfg.Server.ScanConcurrency)
	}
	return &Server{cfg: cfg, router: r, srv: srv, cm: cm, wkr: wkr, handlers: apiHandlers}
}

// Routes returns the chi router so handler packages can register their
// endpoints. Not goroutine-safe; call from setup only, before Run.
func (s *Server) Routes() chi.Router { return s.router }

// StartWorker starts the in-process job worker. Run() invokes this
// automatically; tests that bypass Run() (e.g., httptest.NewServer
// against s.router) must call it explicitly when they need the worker
// to drain jobs.
func (s *Server) StartWorker(ctx context.Context) {
	if s.wkr != nil {
		s.wkr.Start(ctx)
	}
}

// StopWorker stops the in-process job worker. Idempotent.
func (s *Server) StopWorker() {
	if s.wkr != nil {
		s.wkr.Stop()
	}
}

// Run starts the HTTPS listener and blocks until ctx is canceled. On
// cancellation, srv.Shutdown is called with a 30s grace period.
//
// Returns nil on graceful shutdown, or the underlying ListenAndServeTLS
// error otherwise.
func (s *Server) Run(ctx context.Context) error {
	// Backstop: writers go through the slog default; the correlation
	// handler is configured by main.go before calling Run.
	slog.InfoContext(ctx, "openwatch server starting",
		slog.String("listen", s.cfg.Server.Listen),
		slog.String("tls_cert", s.cfg.Server.TLSCert),
	)

	// Start the in-process worker (DoD step 16) BEFORE the listener so any
	// jobs enqueued during boot are eligible for drain.
	if s.wkr != nil {
		s.wkr.Start(ctx)
	}

	listenErr := make(chan error, 1)
	go func() {
		// Cert/key file paths are passed to ListenAndServeTLS as fallback;
		// our TLSConfig.GetCertificate is consulted on every handshake so
		// the file args are not authoritative. Passing them is required by
		// the stdlib API.
		err := s.srv.ListenAndServeTLS(s.cfg.Server.TLSCert, s.cfg.Server.TLSKey)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			return
		}
		listenErr <- nil
	}()

	select {
	case <-ctx.Done():
		slog.InfoContext(ctx, "openwatch server shutting down (ctx canceled)")
		if s.wkr != nil {
			s.wkr.Stop()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		shutdownErr := s.srv.Shutdown(shutdownCtx)
		// ALWAYS drain listenErr to prevent goroutine leak. Even when
		// Shutdown errors, the inner goroutine eventually returns via
		// http.ErrServerClosed; we must read its result either way.
		listenErrResult := <-listenErr
		if shutdownErr != nil {
			return fmt.Errorf("server: shutdown: %w", shutdownErr)
		}
		return listenErrResult
	case err := <-listenErr:
		return err
	}
}
