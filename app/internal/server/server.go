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

	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/idempotency"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/Hanalyx/openwatch/internal/worker"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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

// New constructs a Server from validated config and DB pool. The returned
// Server has the foundation middleware chain mounted (correlation first,
// then idempotency) and the Stage-0 API routes generated from
// app/api/openapi.yaml registered.
func New(cfg *config.Config, pool *pgxpool.Pool) *Server {
	r := chi.NewRouter()

	// FIRST middleware in the chain — every other layer (audit, logging,
	// auth, idempotency) depends on correlation_id being on context.
	r.Use(correlation.HTTPMiddleware)

	// Identity binder. Reads session cookie or Bearer JWT, translates to
	// auth.Identity via the users.Service Lookups adapter. Sets a
	// non-anonymous Identity on success (anonymous if not). Does NOT
	// reject on its own — that's the handler's job via EnforcePermission.
	// Per app/specs/system/auth-identity.spec.yaml AC-17.
	usrSvc := users.NewService(pool, nil)
	r.Use(identity.Binder(pool, usrSvc))

	// Idempotency middleware: short-circuits replays of mutating requests
	// that include an Idempotency-Key header. No-op for GET/HEAD/OPTIONS.
	// Per app/specs/system/idempotency.spec.yaml.
	r.Use(idempotency.Middleware(pool))

	// chi's default NotFound/MethodNotAllowed handlers short-circuit
	// AROUND the middleware chain. Register explicit handlers so 404 and
	// 405 responses also carry X-Correlation-Id.
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "404 page not found", http.StatusNotFound)
	})
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

	// Stage-0 in-process worker that drains diagnostics.test_job from the
	// queue. Started by Run, stopped on shutdown. Spec
	// release-stage-0-signoff AC-10.
	var wkr *worker.Worker
	if pool != nil {
		wkr = worker.New(pool)
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
