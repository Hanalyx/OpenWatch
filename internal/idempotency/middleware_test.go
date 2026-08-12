// @spec system-idempotency
//
// AC traceability:
//   AC-01  TestIdempotency_FirstWriteRecordsCacheEntry
//   AC-02  TestIdempotency_ReplaySameKeyAndBodyReturnsCachedResponse
//   AC-03  TestIdempotency_ReplaySameKeyDifferentBodyReturns409
//   AC-04  TestIdempotency_MissingKeyMiddlewareNoOp
//   AC-05  TestIdempotency_GetRequestPassesThroughUnchanged
//   AC-06  TestIdempotency_NonSuccessResponsesNotCached
//   AC-07  TestIdempotency_LookupLatencyP99
//   AC-08  TestIdempotency_ExpiredEntryIsCacheMiss
//   AC-09  TestIdempotency_ConcurrentRaceProducesOneEffect
//   AC-10  TestIdempotency_AnonymousCallerNeverTouchesCache
//   AC-11  TestIdempotency_CrossActorReplayIsPlainMiss
//   AC-12  TestIdempotency_HashCoversRouteNotOnlyBody
//   AC-13  TestIdempotency_DenialIsNeverCached
//   AC-14  TestIdempotency_SameKeyDifferentActorsCoexist
//
// The tests below reach the middleware only through Middleware() and
// auth.SetIdentity, plus raw SQL for seeding and inspection. They never call
// the unexported store, lookup or hashRequest. The expected request hash is
// recomputed here from the canonical string in C-07, so the encoding is
// pinned by an independent implementation rather than by the one under test.

package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/perftest"
	"github.com/jackc/pgx/v5/pgxpool"
)

// jsonEqual asserts two JSON byte slices are semantically equal (ignoring
// whitespace differences from JSONB storage normalization).
func jsonEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var g, w interface{}
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("unmarshal got: %v (raw: %q)", err, got)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("unmarshal want: %v (raw: %q)", err, want)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("not JSON-equal: got %q, want %q", got, want)
	}
}

// freshPool returns a pool against a clean idempotency_keys table.
func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE idempotency_keys")
	return pool
}

// wantHash recomputes the canonical request hash from C-07:
// sha256(method + "\n" + escaped_path + "\n" + raw_query + "\n" + body).
// Written out here on purpose. The middleware's own hashRequest is the code
// under test, so it cannot be the oracle for its own encoding.
func wantHash(method, escapedPath, rawQuery, body string) string {
	sum := sha256.Sum256([]byte(method + "\n" + escapedPath + "\n" + rawQuery + "\n" + body))
	return hex.EncodeToString(sum[:])
}

// authed binds an authenticated identity onto the request, the way the
// identity binder does in production before this middleware runs.
func authed(r *http.Request, actorID string, role auth.RoleID) *http.Request {
	return r.WithContext(auth.SetIdentity(r.Context(), auth.Identity{
		ID:     actorID,
		RoleID: role,
	}))
}

// postAs builds an authenticated POST for the given actor.
func postAs(actorID, target, body string, key string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set(HeaderName, key)
	return authed(req, actorID, auth.RoleAdmin)
}

// echoHandler counts invocations and answers 201 with the calling actor's
// ID in the body. The actor in the body is what makes a cross-actor replay
// visible: if B is served A's cached response, B sees A's ID.
type echoHandler struct {
	invocations atomic.Int64
}

func (h *echoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.invocations.Add(1)
	body := make([]byte, r.ContentLength)
	_, _ = r.Body.Read(body)
	actor := auth.FromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"echoed":true,"actor":"` + actor.ID + `"}`))
}

// storedRow is one inspected idempotency_keys row.
type storedRow struct {
	ActorID   string
	Key       string
	Hash      string
	Status    int
	Body      []byte
	ExpiresAt time.Time
}

// readRow reads the row at (actorID, key). ok is false when there is none.
func readRow(t *testing.T, pool *pgxpool.Pool, actorID, key string) (storedRow, bool) {
	t.Helper()
	var row storedRow
	err := pool.QueryRow(context.Background(),
		`SELECT actor_id, key, request_hash, response_status, response_body, expires_at
		 FROM idempotency_keys WHERE actor_id = $1 AND key = $2`,
		actorID, key).Scan(&row.ActorID, &row.Key, &row.Hash, &row.Status, &row.Body, &row.ExpiresAt)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return storedRow{}, false
		}
		t.Fatalf("read row (%s, %s): %v", actorID, key, err)
	}
	return row, true
}

// countKey counts rows for a key across all actors. Schema-agnostic on
// purpose: it answers "was anything written for this key at all".
func countKey(t *testing.T, pool *pgxpool.Pool, key string) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM idempotency_keys WHERE key = $1`, key).Scan(&n); err != nil {
		t.Fatalf("count rows for key %q: %v", key, err)
	}
	return n
}

// @ac AC-01
func TestIdempotency_FirstWriteRecordsCacheEntry(t *testing.T) {
	t.Run("system-idempotency/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		handler := &echoHandler{}
		mw := Middleware(pool)(handler)

		const body = `{"x":1}`
		before := time.Now()
		req := postAs("actor-a", "/test?a=1", body, "key-001")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)

		if handler.invocations.Load() != 1 {
			t.Errorf("handler invocations = %d, want 1", handler.invocations.Load())
		}

		row, ok := readRow(t, pool, "actor-a", "key-001")
		if !ok {
			t.Fatal("no row at (actor-a, key-001)")
		}
		if row.ActorID != "actor-a" {
			t.Errorf("actor_id = %q, want %q", row.ActorID, "actor-a")
		}
		if want := wantHash("POST", "/test", "a=1", body); row.Hash != want {
			t.Errorf("request_hash = %q, want %q (sha256 over method, path, query, body)", row.Hash, want)
		}
		if row.Status != http.StatusCreated {
			t.Errorf("cached status = %d, want 201", row.Status)
		}
		// TTL is 24h from first-seen (C-04). One minute of slack covers the
		// gap between the reading of before and the middleware's own clock.
		wantExpiry := before.Add(TTL)
		if d := row.ExpiresAt.Sub(wantExpiry); d < -time.Minute || d > time.Minute {
			t.Errorf("expires_at = %v, want within 1m of %v (now + 24h)", row.ExpiresAt, wantExpiry)
		}
	})
}

// @ac AC-02
func TestIdempotency_ReplaySameKeyAndBodyReturnsCachedResponse(t *testing.T) {
	t.Run("system-idempotency/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		handler := &echoHandler{}
		mw := Middleware(pool)(handler)

		rec1 := httptest.NewRecorder()
		mw.ServeHTTP(rec1, postAs("actor-a", "/test", `{"x":1}`, "key-replay"))
		first := rec1.Body.String()
		firstStatus := rec1.Code

		rec2 := httptest.NewRecorder()
		mw.ServeHTTP(rec2, postAs("actor-a", "/test", `{"x":1}`, "key-replay"))

		// Handler should have been invoked exactly once (replay hit cache).
		if handler.invocations.Load() != 1 {
			t.Errorf("handler invocations = %d, want 1 (replay should skip handler)",
				handler.invocations.Load())
		}
		if rec2.Code != firstStatus {
			t.Errorf("replay status = %d, want %d", rec2.Code, firstStatus)
		}
		// JSON-equal (JSONB storage normalizes whitespace; AC-02 was
		// relaxed from byte-for-byte to semantic equality).
		jsonEqual(t, rec2.Body.Bytes(), []byte(first))
	})
}

// @ac AC-03
func TestIdempotency_ReplaySameKeyDifferentBodyReturns409(t *testing.T) {
	t.Run("system-idempotency/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		handler := &echoHandler{}
		mw := Middleware(pool)(handler)

		mw.ServeHTTP(httptest.NewRecorder(), postAs("actor-a", "/test", `{"x":1}`, "key-conflict"))

		// Same key, same route, different body: a different request hash.
		rec2 := httptest.NewRecorder()
		mw.ServeHTTP(rec2, postAs("actor-a", "/test", `{"x":2}`, "key-conflict"))

		if rec2.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409", rec2.Code)
		}
		if !strings.Contains(rec2.Body.String(), "idempotency.key_reused") {
			t.Errorf("body lacks idempotency.key_reused: %s", rec2.Body.String())
		}
		if strings.Contains(rec2.Body.String(), "echoed") {
			t.Errorf("first response was replayed instead of 409: %s", rec2.Body.String())
		}
		// Handler should have run exactly once (the first call).
		if handler.invocations.Load() != 1 {
			t.Errorf("handler invocations = %d, want 1", handler.invocations.Load())
		}
		// The stored row still carries the first request's hash.
		row, ok := readRow(t, pool, "actor-a", "key-conflict")
		if !ok {
			t.Fatal("no row at (actor-a, key-conflict)")
		}
		if want := wantHash("POST", "/test", "", `{"x":1}`); row.Hash != want {
			t.Errorf("request_hash = %q, want the first request's hash %q", row.Hash, want)
		}
	})
}

// @ac AC-04
// AC-04: Mutating request without Idempotency-Key passes through the
// middleware unchanged. The handler is responsible for returning
// 400 idempotency.key_required. This test verifies the middleware
// honors that contract by NOT caching, NOT writing rows, and NOT
// hijacking the response when the header is absent.
func TestIdempotency_MissingKeyMiddlewareNoOp(t *testing.T) {
	t.Run("system-idempotency/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		handler := &echoHandler{}
		mw := Middleware(pool)(handler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"x":1}`))
		// No Idempotency-Key header.
		req = authed(req, "actor-a", auth.RoleAdmin)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)

		// Handler ran (middleware did not block or transform).
		if handler.invocations.Load() != 1 {
			t.Errorf("handler invocations = %d, want 1", handler.invocations.Load())
		}
		// Handler's 201 came through unmodified.
		if rec.Code != http.StatusCreated {
			t.Errorf("status = %d, want 201 (handler response, not middleware-injected)", rec.Code)
		}
		// No row written: the middleware skipped the cache write path.
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM idempotency_keys`).Scan(&count)
		if count != 0 {
			t.Errorf("idempotency_keys row count = %d, want 0 (no header, no cache)", count)
		}
	})
}

// @ac AC-05
func TestIdempotency_GetRequestPassesThroughUnchanged(t *testing.T) {
	t.Run("system-idempotency/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		handler := &echoHandler{}
		mw := Middleware(pool)(handler)

		// Two GET calls with same Idempotency-Key: both should reach handler.
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set(HeaderName, "get-key")
			mw.ServeHTTP(httptest.NewRecorder(), authed(req, "actor-a", auth.RoleAdmin))
		}

		if handler.invocations.Load() != 2 {
			t.Errorf("handler invocations = %d, want 2 (GET should bypass cache)",
				handler.invocations.Load())
		}
		if n := countKey(t, pool, "get-key"); n != 0 {
			t.Errorf("cache row count = %d, want 0 (GET should not write)", n)
		}
	})
}

// @ac AC-06
func TestIdempotency_NonSuccessResponsesNotCached(t *testing.T) {
	t.Run("system-idempotency/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		var calls atomic.Int64
		failHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		mw := Middleware(pool)(failHandler)

		// Two POSTs with same key: neither should be cached (both 500).
		for i := 0; i < 2; i++ {
			mw.ServeHTTP(httptest.NewRecorder(), postAs("actor-a", "/test", `{"x":1}`, "fail-key"))
		}

		if calls.Load() != 2 {
			t.Errorf("handler invocations = %d, want 2 (5xx must not be cached)", calls.Load())
		}
		if n := countKey(t, pool, "fail-key"); n != 0 {
			t.Errorf("cache row count = %d, want 0 (5xx must not be stored)", n)
		}
	})
}

// @ac AC-07
// AC-07: Cache lookup latency p99 < 5ms against local DB. Populates one
// row, then measures the hot path (key match, cached body returned).
func TestIdempotency_LookupLatencyP99(t *testing.T) {
	t.Run("system-idempotency/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		handler := &echoHandler{}
		mw := Middleware(pool)(handler)

		// Populate one cached row (key=perf-key, body={"x":1}).
		mw.ServeHTTP(httptest.NewRecorder(), postAs("actor-a", "/test", `{"x":1}`, "perf-key"))

		// Now measure replays. These should be cache hits, no handler call.
		baseline := handler.invocations.Load()
		const n = 200
		durs := make([]time.Duration, n)
		for i := 0; i < n; i++ {
			req := postAs("actor-a", "/test", `{"x":1}`, "perf-key")
			start := time.Now()
			mw.ServeHTTP(httptest.NewRecorder(), req)
			durs[i] = time.Since(start)
		}
		if handler.invocations.Load() != baseline {
			t.Errorf("handler ran during replay loop: %d extra calls",
				handler.invocations.Load()-baseline)
		}
		// Sort, then pick p99.
		for i := 1; i < n; i++ {
			v := durs[i]
			j := i - 1
			for j >= 0 && durs[j] > v {
				durs[j+1] = durs[j]
				j--
			}
			durs[j+1] = v
		}
		p99 := durs[int(float64(n)*0.99)]
		if p99 > 5*time.Millisecond {
			perftest.Budgetf(t, "Cache lookup p99 = %v, want < 5ms", p99)
		}
		t.Logf("Cache lookup p99 = %v over %d replays", p99, n)
	})
}

// @ac AC-08
func TestIdempotency_ExpiredEntryIsCacheMiss(t *testing.T) {
	t.Run("system-idempotency/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		handler := &echoHandler{}
		mw := Middleware(pool)(handler)

		// Seed a row for this actor and key that expired an hour ago.
		_, err := pool.Exec(context.Background(),
			`INSERT INTO idempotency_keys (actor_id, key, request_hash, response_status, response_body, expires_at)
			 VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
			"actor-a", "expired-key", wantHash("POST", "/test", "", `{"x":1}`),
			201, `{"stale":true}`, time.Now().Add(-1*time.Hour))
		if err != nil {
			t.Fatalf("seed expired row: %v", err)
		}

		// Replay: should be a miss, so the handler runs and overwrites.
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, postAs("actor-a", "/test", `{"x":1}`, "expired-key"))

		if handler.invocations.Load() != 1 {
			t.Errorf("handler invocations = %d, want 1 (expired entry must be miss)",
				handler.invocations.Load())
		}
		if strings.Contains(rec.Body.String(), "stale") {
			t.Error("response body included stale cached content")
		}
		// The row for that same actor and key was overwritten, not duplicated.
		if n := countKey(t, pool, "expired-key"); n != 1 {
			t.Errorf("rows for expired-key = %d, want 1 (overwrite, not insert)", n)
		}
		row, ok := readRow(t, pool, "actor-a", "expired-key")
		if !ok {
			t.Fatal("no row at (actor-a, expired-key) after the miss")
		}
		if row.ExpiresAt.Before(time.Now()) {
			t.Errorf("expires_at = %v, want a future time after the overwrite", row.ExpiresAt)
		}
	})
}

// @ac AC-09
func TestIdempotency_ConcurrentRaceProducesOneEffect(t *testing.T) {
	t.Run("system-idempotency/AC-09", func(t *testing.T) {
		pool := freshPool(t)
		handler := &echoHandler{}
		mw := Middleware(pool)(handler)

		const n = 10
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodPost, "/test",
					bytes.NewReader([]byte(`{"x":1}`)))
				req.Header.Set(HeaderName, "race-key")
				mw.ServeHTTP(httptest.NewRecorder(), authed(req, "actor-a", auth.RoleAdmin))
			}()
		}
		wg.Wait()

		// The race COULD produce up to n invocations if no DB serialization,
		// but the spec invariant is: one cached row, consistent responses.
		// We assert <= n invocations and exactly 1 cached row.
		if got := countKey(t, pool, "race-key"); got != 1 {
			t.Errorf("cached rows for race-key = %d, want 1", got)
		}
		// Best effort: handler invoked at least once, at most n times.
		// (Without distributed locking, the first-write-wins race is allowed.)
		got := handler.invocations.Load()
		if got < 1 || got > n {
			t.Errorf("handler invocations = %d, want in [1, %d]", got, n)
		}
	})
}

// @ac AC-10
// AC-10: an anonymous caller does not touch the cache in either direction.
//
// Two assertions, and the second one is the load-bearing half. A test that
// only checks "nothing was written" passes against code that skips the
// write but still replays, which is the exact shape of the defect this
// clause exists to stop. So part two seeds a row whose hash matches the
// anonymous request and proves it is not served back.
func TestIdempotency_AnonymousCallerNeverTouchesCache(t *testing.T) {
	t.Run("system-idempotency/AC-10", func(t *testing.T) {
		pool := freshPool(t)
		handler := &echoHandler{}
		mw := Middleware(pool)(handler)

		// Part one: an anonymous request writes nothing. No identity is set
		// on the context, so auth.FromContext reports anonymous.
		anon1 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"x":1}`))
		anon1.Header.Set(HeaderName, "anon-key")
		rec1 := httptest.NewRecorder()
		mw.ServeHTTP(rec1, anon1)

		if handler.invocations.Load() != 1 {
			t.Errorf("handler invocations = %d, want 1 (anonymous request must reach the handler)",
				handler.invocations.Load())
		}
		if rec1.Code != http.StatusCreated {
			t.Errorf("status = %d, want 201 (handler response)", rec1.Code)
		}
		if n := countKey(t, pool, "anon-key"); n != 0 {
			t.Errorf("rows for anon-key = %d, want 0 (anonymous traffic must not be stored)", n)
		}

		// Part two: a matching row already exists, and the anonymous caller
		// must still not be served from it.
		const seededBody = `{"cached":"for-actor-a"}`
		seedExpiry := time.Now().Add(TTL)
		_, err := pool.Exec(context.Background(),
			`INSERT INTO idempotency_keys (actor_id, key, request_hash, response_status, response_body, expires_at)
			 VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
			"actor-a", "shared-key", wantHash("POST", "/test", "", `{"x":1}`),
			200, seededBody, seedExpiry)
		if err != nil {
			t.Fatalf("seed row at (actor-a, shared-key): %v", err)
		}

		anon2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"x":1}`))
		anon2.Header.Set(HeaderName, "shared-key")
		rec2 := httptest.NewRecorder()
		mw.ServeHTTP(rec2, anon2)

		if handler.invocations.Load() != 2 {
			t.Errorf("handler invocations = %d, want 2 (the seeded row must not short-circuit the handler)",
				handler.invocations.Load())
		}
		if rec2.Code != http.StatusCreated {
			t.Errorf("status = %d, want 201 (handler response, not the seeded 200)", rec2.Code)
		}
		if strings.Contains(rec2.Body.String(), "for-actor-a") {
			t.Errorf("anonymous caller was served actor-a's cached body: %s", rec2.Body.String())
		}
		if rec2.Code == http.StatusConflict {
			t.Error("anonymous caller got 409; the middleware must not consult the cache at all")
		}

		// The seeded row is untouched: same hash, status, body and expiry.
		row, ok := readRow(t, pool, "actor-a", "shared-key")
		if !ok {
			t.Fatal("seeded row at (actor-a, shared-key) is gone")
		}
		if row.Status != 200 {
			t.Errorf("seeded response_status = %d, want 200 (unchanged)", row.Status)
		}
		jsonEqual(t, row.Body, []byte(seededBody))
		if d := row.ExpiresAt.Sub(seedExpiry); d < -time.Second || d > time.Second {
			t.Errorf("seeded expires_at = %v, want unchanged %v", row.ExpiresAt, seedExpiry)
		}
		if n := countKey(t, pool, "shared-key"); n != 1 {
			t.Errorf("rows for shared-key = %d, want 1 (the anonymous call must add none)", n)
		}
	})
}

// @ac AC-11
// AC-11: a cross-actor replay is a plain miss, not a 409.
//
// The order of the assertions matters. B's own response is checked before
// any row inspection, so code that serves B actor A's cached response fails
// on the behavior rather than on a schema detail.
func TestIdempotency_CrossActorReplayIsPlainMiss(t *testing.T) {
	t.Run("system-idempotency/AC-11", func(t *testing.T) {
		pool := freshPool(t)
		handler := &echoHandler{}
		mw := Middleware(pool)(handler)

		// Actor A caches a response at (actor-a, K).
		recA := httptest.NewRecorder()
		mw.ServeHTTP(recA, postAs("actor-a", "/test", `{"x":1}`, "shared-key"))
		if !strings.Contains(recA.Body.String(), `"actor":"actor-a"`) {
			t.Fatalf("setup: A's response = %s, want A's own", recA.Body.String())
		}
		beforeA, ok := readRow(t, pool, "actor-a", "shared-key")
		if !ok {
			t.Fatal("setup: no row at (actor-a, shared-key)")
		}

		// Actor B sends the same key, method, path and body.
		recB := httptest.NewRecorder()
		mw.ServeHTTP(recB, postAs("actor-b", "/test", `{"x":1}`, "shared-key"))

		// B ran the handler, so B's own authorization applied.
		if recB.Code == http.StatusConflict {
			t.Errorf("B got 409; a key held by another actor must read as a plain miss, "+
				"never as an existence oracle: %s", recB.Body.String())
		}
		if recB.Code != http.StatusCreated {
			t.Errorf("B status = %d, want 201 (B's own handler response)", recB.Code)
		}
		if !strings.Contains(recB.Body.String(), `"actor":"actor-b"`) {
			t.Errorf("B was served %s, want B's own response. A cached response from "+
				"another actor was replayed, skipping B's authorization", recB.Body.String())
		}
		if handler.invocations.Load() != 2 {
			t.Errorf("handler invocations = %d, want 2 (B must run the handler)",
				handler.invocations.Load())
		}

		// A row now exists at (actor-b, K), and A's row is unchanged.
		rowB, ok := readRow(t, pool, "actor-b", "shared-key")
		if !ok {
			t.Fatal("no row at (actor-b, shared-key)")
		}
		if !strings.Contains(string(rowB.Body), "actor-b") {
			t.Errorf("row at (actor-b, shared-key) holds %q, want B's own response", rowB.Body)
		}

		afterA, ok := readRow(t, pool, "actor-a", "shared-key")
		if !ok {
			t.Fatal("A's row disappeared after B's call")
		}
		if afterA.Hash != beforeA.Hash {
			t.Errorf("A's request_hash changed: %q -> %q", beforeA.Hash, afterA.Hash)
		}
		if afterA.Status != beforeA.Status {
			t.Errorf("A's response_status changed: %d -> %d", beforeA.Status, afterA.Status)
		}
		jsonEqual(t, afterA.Body, beforeA.Body)
		// An unchanged expiry proves B's call did not refresh A's TTL.
		if d := afterA.ExpiresAt.Sub(beforeA.ExpiresAt); d < -time.Second || d > time.Second {
			t.Errorf("A's expires_at changed: %v -> %v", beforeA.ExpiresAt, afterA.ExpiresAt)
		}
		if n := countKey(t, pool, "shared-key"); n != 2 {
			t.Errorf("rows for shared-key = %d, want 2 (one per actor)", n)
		}
	})
}

// @ac AC-12
// AC-12: the hash covers the route, not only the body. Same actor, same key
// and same body on a different path, method or query is a different request,
// so it must be 409 rather than a replay of the first response.
func TestIdempotency_HashCoversRouteNotOnlyBody(t *testing.T) {
	t.Run("system-idempotency/AC-12", func(t *testing.T) {
		const body = `{"x":1}`
		cases := []struct {
			name   string
			key    string
			method string
			target string
		}{
			{"different path", "route-key-path", http.MethodPost, "/other"},
			{"different method", "route-key-method", http.MethodPut, "/test"},
			{"different query", "route-key-query", http.MethodPost, "/test?a=2"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pool := freshPool(t)
				handler := &echoHandler{}
				mw := Middleware(pool)(handler)

				// First call: POST /test?a=1 with body B.
				mw.ServeHTTP(httptest.NewRecorder(),
					postAs("actor-a", "/test?a=1", body, tc.key))

				// Second call: same key, same body, one route element changed.
				req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(body))
				req.Header.Set(HeaderName, tc.key)
				rec := httptest.NewRecorder()
				mw.ServeHTTP(rec, authed(req, "actor-a", auth.RoleAdmin))

				if rec.Code != http.StatusConflict {
					t.Errorf("status = %d, want 409 (the route is part of the hash)", rec.Code)
				}
				if !strings.Contains(rec.Body.String(), "idempotency.key_reused") {
					t.Errorf("body lacks idempotency.key_reused: %s", rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), "echoed") {
					t.Errorf("the first route's response was replayed: %s", rec.Body.String())
				}
				if handler.invocations.Load() != 1 {
					t.Errorf("handler invocations = %d, want 1 (only the first call)",
						handler.invocations.Load())
				}
			})
		}
	})
}

// @ac AC-13
// AC-13: a denial is never cached. A cached denial would pin a 401 or a 403
// to a key for 24 hours, so granting the permission would change nothing
// until the entry expired.
func TestIdempotency_DenialIsNeverCached(t *testing.T) {
	t.Run("system-idempotency/AC-13", func(t *testing.T) {
		// A route that needs host:write. Viewer lacks it, admin holds it.
		guarded := func(calls *atomic.Int64) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if !auth.FromContext(r.Context()).HasPermission(auth.HostWrite) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":{"code":"rbac.forbidden"}}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"granted":true}`))
			})
		}

		t.Run("403 then grant", func(t *testing.T) {
			pool := freshPool(t)
			var calls atomic.Int64
			mw := Middleware(pool)(guarded(&calls))

			// Actor B lacks host:write.
			denied := httptest.NewRequest(http.MethodPost, "/hosts", strings.NewReader(`{"x":1}`))
			denied.Header.Set(HeaderName, "denied-key")
			rec1 := httptest.NewRecorder()
			mw.ServeHTTP(rec1, authed(denied, "actor-b", auth.RoleViewer))

			if rec1.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (setup: viewer must lack host:write)", rec1.Code)
			}
			if n := countKey(t, pool, "denied-key"); n != 0 {
				t.Errorf("rows for denied-key = %d, want 0 (a denial must not be cached)", n)
			}

			// Same actor, same key, now holding the permission.
			granted := httptest.NewRequest(http.MethodPost, "/hosts", strings.NewReader(`{"x":1}`))
			granted.Header.Set(HeaderName, "denied-key")
			rec2 := httptest.NewRecorder()
			mw.ServeHTTP(rec2, authed(granted, "actor-b", auth.RoleAdmin))

			if rec2.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 (the grant must take effect, not a replayed denial)",
					rec2.Code)
			}
			if strings.Contains(rec2.Body.String(), "rbac.forbidden") {
				t.Errorf("the denial was replayed after the grant: %s", rec2.Body.String())
			}
			if calls.Load() != 2 {
				t.Errorf("handler invocations = %d, want 2 (both calls must reach the handler)",
					calls.Load())
			}
		})

		t.Run("401 is not cached", func(t *testing.T) {
			pool := freshPool(t)
			var calls atomic.Int64
			unauthorized := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":"auth.session_invalid"}}`))
			})
			mw := Middleware(pool)(unauthorized)

			for i := 0; i < 2; i++ {
				mw.ServeHTTP(httptest.NewRecorder(),
					postAs("actor-b", "/hosts", `{"x":1}`, "unauth-key"))
			}
			if calls.Load() != 2 {
				t.Errorf("handler invocations = %d, want 2 (a 401 must not be cached)", calls.Load())
			}
			if n := countKey(t, pool, "unauth-key"); n != 0 {
				t.Errorf("rows for unauth-key = %d, want 0 (a 401 must not be stored)", n)
			}
		})
	})
}

// @ac AC-14
// AC-14: the primary key is the composite (actor_id, key). Two rows with the
// same key and different actor_id coexist. The assertion is that BOTH rows
// survive, not merely that the second insert returned no error: a key-only
// primary key with an upsert would also return no error while destroying the
// first row.
func TestIdempotency_SameKeyDifferentActorsCoexist(t *testing.T) {
	t.Run("system-idempotency/AC-14", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		const insert = `INSERT INTO idempotency_keys
			(actor_id, key, request_hash, response_status, response_body, expires_at)
			VALUES ($1, $2, $3, $4, $5::jsonb, $6)`

		if _, err := pool.Exec(ctx, insert,
			"actor-a", "same-key", "hash-a", 201, `{"owner":"a"}`,
			time.Now().Add(TTL)); err != nil {
			t.Fatalf("insert row for actor-a: %v", err)
		}
		if _, err := pool.Exec(ctx, insert,
			"actor-b", "same-key", "hash-b", 200, `{"owner":"b"}`,
			time.Now().Add(TTL)); err != nil {
			t.Fatalf("insert row for actor-b: %v", err)
		}

		if n := countKey(t, pool, "same-key"); n != 2 {
			t.Errorf("rows for same-key = %d, want 2 (both actors keep their own row)", n)
		}

		rowA, ok := readRow(t, pool, "actor-a", "same-key")
		if !ok {
			t.Fatal("actor-a's row is gone; the second insert overwrote it")
		}
		if rowA.Hash != "hash-a" || rowA.Status != 201 {
			t.Errorf("actor-a's row = (%q, %d), want (hash-a, 201) unchanged", rowA.Hash, rowA.Status)
		}
		jsonEqual(t, rowA.Body, []byte(`{"owner":"a"}`))

		rowB, ok := readRow(t, pool, "actor-b", "same-key")
		if !ok {
			t.Fatal("actor-b's row is missing")
		}
		if rowB.Hash != "hash-b" || rowB.Status != 200 {
			t.Errorf("actor-b's row = (%q, %d), want (hash-b, 200)", rowB.Hash, rowB.Status)
		}
		jsonEqual(t, rowB.Body, []byte(`{"owner":"b"}`))
	})
}
