package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Session lifecycle errors. The identity binder middleware translates
// these to specific auth.login.failure audit reasons.
//
// Spec system-auth-identity AC-08, AC-10, C-11.
var (
	ErrSessionNotFound = errors.New("identity: session not found")
	ErrSessionRevoked  = errors.New("identity: session revoked")
	ErrSessionExpired  = errors.New("identity: session expired")
)

// Default inactivity + absolute timeout windows. These are the baseline
// per spec C-06; a security admin may override them via the auth policy
// (Settings -> Security). The defaults preserve the historical behaviour
// (15-minute idle, 12-hour absolute) until the policy changes them.
const (
	DefaultSessionInactivityWindow = 15 * time.Minute
	DefaultSessionAbsoluteWindow   = 12 * time.Hour
	// SessionTokenBytes is the entropy of the presentation token. 32 bytes
	// (256-bit) per spec C-05.
	SessionTokenBytes = 32
)

// Windows carries the active session timeout configuration. The idle
// window bounds inactivity; the absolute window caps total lifetime
// regardless of activity.
//
// Spec system-auth-policy C-02, system-auth-identity C-06.
type Windows struct {
	Idle     time.Duration
	Absolute time.Duration
}

// sessionWindows holds the active windows, swappable at runtime by the
// auth-policy service. An atomic pointer keeps the read path (every
// session verification) lock-free; the default (nil) preserves the
// historical constants so code paths that never set a policy — and tests
// — behave exactly as before.
var sessionWindows atomic.Pointer[Windows]

// SetSessionWindows installs the active session timeout windows. Called at
// startup once the auth policy is loaded, and again whenever an admin
// updates the policy. Non-positive fields fall back to the defaults so a
// malformed policy can never disable session expiry.
//
// Spec system-auth-policy AC-05.
func SetSessionWindows(w Windows) {
	if w.Idle <= 0 {
		w.Idle = DefaultSessionInactivityWindow
	}
	if w.Absolute <= 0 {
		w.Absolute = DefaultSessionAbsoluteWindow
	}
	sessionWindows.Store(&w)
}

// CurrentWindows returns the active windows, or the defaults when no
// policy has been installed.
func CurrentWindows() Windows {
	if w := sessionWindows.Load(); w != nil {
		return *w
	}
	return Windows{Idle: DefaultSessionInactivityWindow, Absolute: DefaultSessionAbsoluteWindow}
}

// RefreshCookieName is the HttpOnly cookie carrying the refresh token's
// presentation form. Set at login and rotated by the refresh-cookie
// endpoint. JS cannot read it; only the server consumes it.
// Spec system-auth-identity C-13.
const RefreshCookieName = "openwatch_refresh"

// Session is the in-memory shape returned to handlers. The presentation
// token is only present at issuance — verifications and DB reads return
// just the metadata.
type Session struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	CreatedAt         time.Time
	LastSeen          time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	RemoteAddr        string
	UserAgent         string
}

// IssueSession persists a new session row and returns the presentation-
// form token. The token is hashed with SHA-256 before storage; the
// presentation form is never stored anywhere.
//
// Spec AC-06, C-05, C-06.
func IssueSession(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, remoteAddr, userAgent string) (token string, sess Session, err error) {
	return IssueSessionWithAbsolute(ctx, pool, userID, remoteAddr, userAgent,
		time.Now().UTC().Add(CurrentWindows().Absolute))
}

// IssueSessionWithAbsolute is IssueSession with an explicit absolute deadline,
// used by the cookie-refresh path to carry the ORIGINAL login's absolute
// ceiling onto a re-minted session instead of granting a fresh window (AUTH-1
// b). The idle expiry is capped at the absolute deadline, so a session minted
// close to its ceiling expires at the ceiling, not idle+window beyond it.
func IssueSessionWithAbsolute(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, remoteAddr, userAgent string, absoluteExpiresAt time.Time) (token string, sess Session, err error) {
	raw := make([]byte, SessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", Session{}, fmt.Errorf("identity: read session entropy: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))

	id, err := uuid.NewV7()
	if err != nil {
		return "", Session{}, fmt.Errorf("identity: uuid: %w", err)
	}
	now := time.Now().UTC()
	win := CurrentWindows()
	// Defensive: a zero deadline would otherwise cap the idle expiry to the zero
	// time and mint an always-expired session. Treat it as "no carried deadline"
	// and grant a fresh absolute window (the IssueSession default).
	if absoluteExpiresAt.IsZero() {
		absoluteExpiresAt = now.Add(win.Absolute)
	}
	expires := now.Add(win.Idle)
	if expires.After(absoluteExpiresAt) {
		expires = absoluteExpiresAt
	}
	sess = Session{
		ID:                id,
		UserID:            userID,
		CreatedAt:         now,
		LastSeen:          now,
		ExpiresAt:         expires,
		AbsoluteExpiresAt: absoluteExpiresAt,
		RemoteAddr:        remoteAddr,
		UserAgent:         userAgent,
	}

	const stmt = `
		INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen,
		                     expires_at, absolute_expires_at, remote_addr, user_agent)
		VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8)`
	if _, err := pool.Exec(ctx, stmt,
		sess.ID, sess.UserID, hash[:], sess.CreatedAt,
		sess.ExpiresAt, sess.AbsoluteExpiresAt,
		nilIfEmpty(sess.RemoteAddr), nilIfEmpty(sess.UserAgent),
	); err != nil {
		return "", Session{}, fmt.Errorf("identity: insert session: %w", err)
	}
	return token, sess, nil
}

// VerifyOption tunes VerifySession. AUTH-1 (c).
type VerifyOption func(*verifyOpts)

type verifyOpts struct{ noSlide bool }

// WithoutSlide validates the session and enforces the idle + absolute
// deadlines, but does NOT advance expires_at/last_seen. The identity binder
// passes this for requests that are NOT user-initiated (background polling,
// SSE), so the server-side idle window tracks REAL user activity rather than
// HTTP traffic — otherwise the SPA's polling keeps every session alive forever.
// AUTH-1 (c).
func WithoutSlide() VerifyOption { return func(o *verifyOpts) { o.noSlide = true } }

// VerifySession looks up the session row by token, applies inactivity +
// absolute timeout rules, and (unless WithoutSlide is passed) touches
// last_seen + extends expires_at.
//
// Spec AC-07, AC-08, AC-10.
func VerifySession(ctx context.Context, pool *pgxpool.Pool, token string, opts ...VerifyOption) (Session, error) {
	var o verifyOpts
	for _, f := range opts {
		f(&o)
	}
	if token == "" {
		return Session{}, ErrSessionNotFound
	}
	hash := sha256.Sum256([]byte(token))
	var s Session
	var revokedAt *time.Time
	var remoteAddr, userAgent *string
	const sel = `
		SELECT id, user_id, created_at, last_seen, expires_at, absolute_expires_at,
		       revoked_at, remote_addr, user_agent
		FROM sessions
		WHERE token_hash = $1`
	err := pool.QueryRow(ctx, sel, hash[:]).Scan(
		&s.ID, &s.UserID, &s.CreatedAt, &s.LastSeen, &s.ExpiresAt, &s.AbsoluteExpiresAt,
		&revokedAt, &remoteAddr, &userAgent,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}
		return Session{}, fmt.Errorf("identity: lookup session: %w", err)
	}
	if revokedAt != nil {
		return Session{}, ErrSessionRevoked
	}
	now := time.Now().UTC()
	if now.After(s.AbsoluteExpiresAt) {
		return Session{}, ErrSessionExpired
	}
	if now.After(s.ExpiresAt) {
		return Session{}, ErrSessionExpired
	}

	// AUTH-1 (c): a non-user-initiated request (background poll, SSE) validates
	// the session but must NOT advance the idle window — otherwise the SPA's
	// polling keeps an unattended session alive indefinitely. Return the
	// validated session as-is without touching last_seen/expires_at.
	if o.noSlide {
		s.RevokedAt = revokedAt
		if remoteAddr != nil {
			s.RemoteAddr = *remoteAddr
		}
		if userAgent != nil {
			s.UserAgent = *userAgent
		}
		return s, nil
	}

	// Touch last_seen and extend expires_at by the inactivity window —
	// but never beyond absolute_expires_at.
	newExpires := now.Add(CurrentWindows().Idle)
	if newExpires.After(s.AbsoluteExpiresAt) {
		newExpires = s.AbsoluteExpiresAt
	}
	const upd = `UPDATE sessions SET last_seen = $1, expires_at = $2 WHERE id = $3`
	if _, err := pool.Exec(ctx, upd, now, newExpires, s.ID); err != nil {
		return Session{}, fmt.Errorf("identity: touch session: %w", err)
	}
	s.LastSeen = now
	s.ExpiresAt = newExpires
	s.RevokedAt = revokedAt
	if remoteAddr != nil {
		s.RemoteAddr = *remoteAddr
	}
	if userAgent != nil {
		s.UserAgent = *userAgent
	}
	return s, nil
}

// RevokeSession marks the session as revoked. Subsequent VerifySession
// calls return ErrSessionRevoked. Idempotent — revoking an already-
// revoked session is a no-op.
//
// Spec AC-09.
func RevokeSession(ctx context.Context, pool *pgxpool.Pool, sessionID uuid.UUID) error {
	const stmt = `UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`
	_, err := pool.Exec(ctx, stmt, sessionID)
	if err != nil {
		return fmt.Errorf("identity: revoke session: %w", err)
	}
	return nil
}

// RevokeAllSessionsForUser is called when refresh-token reuse is
// detected (AC-13) — invalidate every active session for the user so
// the attacker can't pivot to the cookie path.
func RevokeAllSessionsForUser(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID) error {
	const stmt = `UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`
	_, err := pool.Exec(ctx, stmt, userID)
	if err != nil {
		return fmt.Errorf("identity: revoke sessions for user: %w", err)
	}
	return nil
}

// sameToken is the constant-time presentation-form comparison helper
// (used internally; never compares against a raw stored hash). Kept
// for callers that legitimately need to compare two tokens (rare —
// most code uses sha256-then-DB-lookup).
func sameToken(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// nilIfEmpty converts an empty string to nil for *string DB columns —
// keeps NULL in the database instead of empty-string sentinel values.
func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// Silence the lint detector for the helper we keep around for future
// callers in handlers (logout-against-supplied-token path).
var _ = sameToken
