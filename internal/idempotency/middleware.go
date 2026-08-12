// Package idempotency provides the middleware that makes mutating HTTP
// requests safely retryable. A request that arrives with an
// Idempotency-Key header is cached for 24 hours; replay by the same caller
// with the same key and request returns the cached response without
// re-running the handler.
//
// The cache is scoped to the calling identity. A cache hit skips the
// handler, so it also skips every authorization check inside it. Only the
// caller who created an entry can have it replayed.
//
// Spec: specs/system/idempotency.spec.yaml
package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HeaderName is the HTTP header carrying the idempotency key.
const HeaderName = "Idempotency-Key"

// TTL is how long a cached response remains valid. Locked in the spec.
const TTL = 24 * time.Hour

// safeMethods bypass the middleware (per RFC 9110: GET/HEAD/OPTIONS are
// inherently idempotent at the protocol level).
var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

// Middleware wraps mutating handlers with the idempotency cache.
//
// Behavior (per spec system-idempotency v2.0.0):
//
//   - Safe methods (GET/HEAD/OPTIONS) pass through unchanged.
//   - Missing Idempotency-Key passes through (the handler decides whether
//     the header is required; the middleware doesn't enforce presence).
//   - An anonymous caller passes through, uncached. See the skip below.
//   - Cache hit (same actor + same key + same request hash): returns the
//     cached status and a JSON-equal body (JSONB storage normalizes
//     whitespace). Handler is not invoked.
//   - Cache hit (same actor + same key + different request hash): returns
//     409 with error.code = "idempotency.key_reused".
//   - Same key held by a different actor: a plain miss. The handler runs
//     under that caller's own authorization and stores under their own
//     actor. No 409, so the route is not an existence oracle.
//   - Cache miss: runs handler, captures the response, persists to DB on
//     2xx. 4xx/5xx are NOT cached (per AC-6 — failures are not pinned).
func Middleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if safeMethods[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			key := r.Header.Get(HeaderName)
			if key == "" {
				// Missing header: not the middleware's job to reject;
				// handler enforces if it cares.
				next.ServeHTTP(w, r)
				return
			}

			// An anonymous caller gets no cache at all. The identity binder
			// runs before this middleware (internal/server/server.go), so an
			// empty ID here means nothing was bound, not that binding has yet
			// to happen. Skipping here rather than lower down skips the
			// lookup, the 409, the body read and the store in one move.
			//
			// Caching an anonymous response is a defect, not a feature:
			//
			//   - replayCached writes only status, Content-Type and body. It
			//     drops every Set-Cookie. Login sets three (session, CSRF,
			//     refresh), so a replayed login already returned 200 with no
			//     session cookie: a success the client cannot use.
			//   - Login and refresh return AccessToken and RefreshToken in the
			//     body, so caching them writes live credentials as plaintext
			//     JSONB for 24 hours. The row outlives the token.
			//   - POST /auth/logout is CSRF-exempt (the /api/v1/auth/ prefix
			//     in internal/server/csrf.go), is not rate limited (only login
			//     and mfa:verify are), and answers 204, which caches. Nothing
			//     reaps expired rows. That is an unauthenticated unbounded
			//     write into the table, and this skip closes it.
			//
			// No anonymous route declares Idempotency-Key in
			// api/openapi.yaml, so nothing legitimate loses caching here.
			actor := auth.FromContext(r.Context())
			if actor.IsAnonymous || actor.ID == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Read and hash the body. We have to consume r.Body once; the
			// handler still needs it, so we restore it before next.ServeHTTP.
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "could not read request body", http.StatusBadRequest)
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))

			hash := hashRequest(r.Method, r.URL.EscapedPath(), r.URL.RawQuery, body)

			// Look up by (actor, key). Cache hit logic:
			cached, found, err := lookup(r.Context(), pool, actor.ID, key)
			if err != nil {
				slog.WarnContext(r.Context(), "idempotency: lookup failed; bypassing cache",
					slog.String("error", err.Error()),
					slog.String("key", key))
				next.ServeHTTP(w, r)
				return
			}
			if found {
				if cached.RequestHash != hash {
					// AC-3: same key, different body → 409.
					writeKeyReusedError(w, r.Context())
					return
				}
				// AC-2: cache hit, identical request — return cached response.
				replayCached(w, cached)
				return
			}

			// Cache miss — run handler with a response-capturing wrapper.
			rec := &recorder{ResponseWriter: w, status: 0}
			next.ServeHTTP(rec, r)

			// Per AC-6: only cache 2xx responses. Errors re-run.
			if rec.status >= 200 && rec.status < 300 {
				if err := store(r.Context(), pool, actor.ID, key, hash, rec.status, rec.body.Bytes()); err != nil {
					slog.WarnContext(r.Context(), "idempotency: store failed",
						slog.String("error", err.Error()),
						slog.String("key", key))
				}
			}
		})
	}
}

// recorder is a ResponseWriter wrapper that captures both the status code
// and the response body for caching. Must implement http.ResponseWriter
// faithfully so handlers behave normally.
type recorder struct {
	http.ResponseWriter
	status      int
	body        bytes.Buffer
	wroteHeader bool
}

func (r *recorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		// Default 200 if handler writes body without explicit WriteHeader.
		r.WriteHeader(http.StatusOK)
	}
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// hashRequest is SHA-256 in hex over the canonical string
// method + "\n" + escaped_path + "\n" + raw_query + "\n" + body, per spec
// C-07.
//
// The body alone is not enough to identify a request. Two different
// endpoints called with the same key and the same body would share one
// cache entry, and the second would be answered with the first one's
// response. An empty body is common on :action routes, so that collision
// is easy to reach by accident, not only on purpose.
//
// The three separators are unambiguous: a method, an escaped path and a
// raw query cannot contain a newline, and the body comes last. The path is
// taken escaped for that reason, so a decoded %0A cannot move the boundary.
// Empty bodies still hash deterministically and stay comparable across
// requests to the same route.
func hashRequest(method, escapedPath, rawQuery string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte("\n"))
	h.Write([]byte(escapedPath))
	h.Write([]byte("\n"))
	h.Write([]byte(rawQuery))
	h.Write([]byte("\n"))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// cachedRow is one row of idempotency_keys, hydrated into a Go struct.
type cachedRow struct {
	Key            string
	RequestHash    string
	ResponseStatus int
	ResponseBody   []byte
}

// lookup checks the idempotency_keys table; returns (row, true) on a
// fresh hit, (zero, false) on miss or expired.
//
// Scoped to actor: another caller's entry is a plain miss, so the handler
// runs and that caller's own authorization applies. Deliberately NOT a 409.
// writeKeyReusedError fires before any authorization runs, so answering 409
// here would turn the route into an oracle for whether some other caller
// holds a given key.
func lookup(ctx context.Context, pool *pgxpool.Pool, actorID, key string) (cachedRow, bool, error) {
	const q = `
SELECT key, request_hash, response_status, response_body
FROM idempotency_keys
WHERE actor_id = $1 AND key = $2 AND expires_at > now()
`
	var row cachedRow
	var body []byte
	err := pool.QueryRow(ctx, q, actorID, key).Scan(&row.Key, &row.RequestHash, &row.ResponseStatus, &body)
	switch {
	case err == nil:
		row.ResponseBody = body
		return row, true, nil
	case errIsNoRows(err):
		return cachedRow{}, false, nil
	default:
		return cachedRow{}, false, err
	}
}

// store persists a cached response. Best-effort: failures are logged but
// the request itself already returned to the client.
func store(ctx context.Context, pool *pgxpool.Pool, actorID, key, hash string, status int, body []byte) error {
	const q = `
INSERT INTO idempotency_keys (actor_id, key, request_hash, response_status, response_body, expires_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6)
ON CONFLICT (actor_id, key) DO UPDATE
  SET request_hash    = EXCLUDED.request_hash,
      response_status = EXCLUDED.response_status,
      response_body   = EXCLUDED.response_body,
      expires_at      = EXCLUDED.expires_at
`
	if len(body) == 0 {
		body = []byte("null")
	}
	_, err := pool.Exec(ctx, q, actorID, key, hash, status, body, time.Now().Add(TTL))
	return err
}

// replayCached writes the cached response back to the client.
func replayCached(w http.ResponseWriter, row cachedRow) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(row.ResponseStatus)
	_, _ = w.Write(row.ResponseBody)
}

// writeKeyReusedError emits a 409 with the canonical error envelope.
// Per api/error_codes.yaml: idempotency.key_reused, fault=client,
// retryable=false. Includes correlation_id from ctx when present, per
// api_design_principles.md §8.1.
func writeKeyReusedError(w http.ResponseWriter, ctx context.Context) {
	errBody := map[string]any{
		"code":          "idempotency.key_reused",
		"fault":         "client",
		"retryable":     false,
		"human_message": "Idempotency-Key was reused with a different request body",
	}
	if cid, ok := correlation.From(ctx); ok {
		errBody["correlation_id"] = cid
	}
	envelope := map[string]any{"error": errBody}
	body, _ := json.Marshal(envelope)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_, _ = w.Write(body)
}

// errIsNoRows is the pgx-style check for "no row found." Uses errors.Is
// so wrapped errors are still detected.
func errIsNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
