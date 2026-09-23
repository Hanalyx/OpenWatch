package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RefreshTokenWindow is the refresh-token lifetime. 7 days per spec.
const RefreshTokenWindow = 7 * 24 * time.Hour

// Refresh-token errors. Reuse detection is the load-bearing one —
// it triggers a cascade revoke of every session for the user, since
// reuse means the attacker captured a token that we already rotated.
var (
	ErrRefreshTokenNotFound = errors.New("identity: refresh token not found")
	ErrRefreshTokenExpired  = errors.New("identity: refresh token expired")
	ErrRefreshTokenRevoked  = errors.New("identity: refresh token revoked")
	ErrRefreshTokenReused   = errors.New("identity: refresh token reuse detected")
	// ErrRefreshSessionExpired — the refresh token is still inside its 7-day
	// window, but the session's ABSOLUTE deadline (carried through the lineage
	// from login) has passed. Refresh is refused; the user must re-authenticate.
	// AUTH-1 (b).
	ErrRefreshSessionExpired = errors.New("identity: session absolute timeout reached")
)

// RevokeRefreshToken marks the row identified by presentation-token as
// revoked. Idempotent — already-revoked or unknown tokens are silently
// no-op. Used by logout to invalidate the refresh cookie at the same
// time as the session cookie.
//
// Spec AC-24.
func RevokeRefreshToken(ctx context.Context, pool DBTX, token string) error {
	if token == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(token))
	const stmt = `UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`
	_, err := pool.Exec(ctx, stmt, hash[:])
	if err != nil {
		return fmt.Errorf("identity: revoke refresh token: %w", err)
	}
	return nil
}

// IssueRefreshToken persists a new refresh-token row and returns the
// presentation token. Token is stored as SHA-256 hash; presentation
// form is never in the DB.
//
// absoluteExpiresAt is the session's absolute deadline (login time + the
// configured absolute window). It is carried through every rotation so the
// session cannot be refreshed past it (AUTH-1 b). A zero value stores NULL —
// the legacy "no absolute ceiling" behavior, used only by callers that have no
// session deadline to anchor to.
//
// Spec AC-12.
func IssueRefreshToken(ctx context.Context, pool DBTX, userID uuid.UUID, absoluteExpiresAt time.Time) (token string, err error) {
	return IssueRefreshTokenForSession(ctx, pool, userID, uuid.Nil, absoluteExpiresAt)
}

// IssueRefreshTokenForSession is IssueRefreshToken bound to the session
// that issued it, so revoking that session ends the lineage and the
// access tokens minted from it. Spec C-38.
func IssueRefreshTokenForSession(ctx context.Context, pool DBTX, userID, sessionID uuid.UUID, absoluteExpiresAt time.Time) (token string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("identity: refresh entropy: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))

	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("identity: uuid: %w", err)
	}
	const stmt = `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, absolute_expires_at, session_id)
		VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := pool.Exec(ctx, stmt, id, userID, hash[:],
		time.Now().UTC().Add(RefreshTokenWindow), nullableTime(absoluteExpiresAt),
		nullableUUID(sessionID)); err != nil {
		return "", fmt.Errorf("identity: insert refresh: %w", err)
	}
	return token, nil
}

// nullableTime returns nil for the zero time (stored as SQL NULL) or the time
// otherwise — so a missing absolute deadline is recorded honestly as "none".
func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// TokenPair is the result of a successful ConsumeRefreshToken call —
// a new access JWT plus a new refresh token. The caller delivers both
// to the client; the old refresh token is now revoked.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	Claims       Claims
	// AbsoluteExpiresAt is the session's carried absolute deadline (AUTH-1 b),
	// zero when the consumed token had none (legacy). The cookie-refresh handler
	// stamps it onto the re-minted session so the absolute ceiling is preserved
	// across refreshes rather than reset.
	AbsoluteExpiresAt time.Time
	// SessionID is the session this lineage is bound to, Nil for a
	// legacy chain minted before session binding existed.
	SessionID uuid.UUID
	// NewRefreshID identifies the row just written, so a caller that
	// mints a NEW session for this refresh can rebind the row to it
	// inside the same transaction.
	NewRefreshID uuid.UUID
}

// RefreshOutcome classifies what a rotation attempt found. The zero
// value is RefreshOutcomeUnknown and means nothing was determined, so a
// caller that forgets to switch on it cannot fall through to success.
type RefreshOutcome int

const (
	// RefreshOutcomeUnknown is the zero value and authorizes nothing.
	RefreshOutcomeUnknown RefreshOutcome = iota
	// RefreshRotated: the chain advanced and a new pair exists.
	RefreshRotated
	// RefreshNotFound: no row matched the presented token.
	RefreshNotFound
	// RefreshExpired: the token is past its own expiry.
	RefreshExpired
	// RefreshRevoked: the row was revoked.
	RefreshRevoked
	// RefreshReused: the row was already rotated. The caller MUST commit
	// so the family-wide revocation this outcome performed is durable.
	RefreshReused
	// RefreshSessionExpired: the session's absolute ceiling has passed.
	RefreshSessionExpired
)

// MustCommit reports whether an outcome wrote something durable that the
// caller has to commit even when it answers with a failure. Reuse
// detection is that case: it revokes the family, and rolling that back
// would discard the only reaction to a stolen token.
func (o RefreshOutcome) MustCommit() bool { return o == RefreshReused || o == RefreshRotated }

// Err maps an outcome to the error the pool-level API returns.
func (o RefreshOutcome) Err() error {
	switch o {
	case RefreshRotated:
		return nil
	case RefreshNotFound:
		return ErrRefreshTokenNotFound
	case RefreshExpired:
		return ErrRefreshTokenExpired
	case RefreshRevoked:
		return ErrRefreshTokenRevoked
	case RefreshReused:
		return ErrRefreshTokenReused
	case RefreshSessionExpired:
		return ErrRefreshSessionExpired
	default:
		return errors.New("identity: refresh outcome undetermined")
	}
}

// ConsumeRefreshTokenTx performs one rotation step INSIDE the caller's
// transaction. It commits nothing and rolls back nothing: the caller
// owns the transaction, took the per-user lock before calling, and
// commits the rotation together with whatever it issues. Spec C-34.
//
// The returned error is reserved for infrastructure failures. An
// ordinary refusal is an outcome, not an error, so a caller cannot
// mistake "this token was refused" for "the database is down".
func ConsumeRefreshTokenTx(ctx context.Context, tx pgx.Tx, token, role string) (RefreshOutcome, *TokenPair, error) {
	if token == "" {
		return RefreshNotFound, nil, nil
	}
	hash := sha256.Sum256([]byte(token))

	var (
		rowID       uuid.UUID
		userID      uuid.UUID
		expiresAt   time.Time
		absoluteExp *time.Time
		rotatedTo   *uuid.UUID
		revokedAt   *time.Time
		sessionID   *uuid.UUID
	)
	err := tx.QueryRow(ctx, `
		SELECT id, user_id, expires_at, absolute_expires_at, rotated_to_id, revoked_at, session_id
		FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`,
		hash[:],
	).Scan(&rowID, &userID, &expiresAt, &absoluteExp, &rotatedTo, &revokedAt, &sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RefreshNotFound, nil, nil
		}
		return RefreshOutcomeUnknown, nil, fmt.Errorf("identity: refresh lookup: %w", err)
	}

	if revokedAt != nil {
		return RefreshRevoked, nil, nil
	}
	if time.Now().UTC().After(expiresAt) {
		return RefreshExpired, nil, nil
	}
	// AUTH-1 (b): the session's absolute deadline is a hard ceiling.
	// Checked before reuse so an expired-session token fails closed.
	if absoluteExp != nil && time.Now().UTC().After(*absoluteExp) {
		return RefreshSessionExpired, nil, nil
	}
	if rotatedTo != nil {
		// Reuse. Somebody holds a token we already rotated away.
		if _, err := tx.Exec(ctx,
			`UPDATE refresh_tokens SET reuse_detected_at = now() WHERE id = $1`,
			rowID); err != nil {
			return RefreshOutcomeUnknown, nil, fmt.Errorf("identity: mark reuse: %w", err)
		}
		if err := RevokeUserCredentials(ctx, tx, userID); err != nil {
			return RefreshOutcomeUnknown, nil, err
		}
		return RefreshReused, nil, nil
	}

	newRefresh := make([]byte, 32)
	if _, err := rand.Read(newRefresh); err != nil {
		return RefreshOutcomeUnknown, nil, fmt.Errorf("identity: refresh entropy: %w", err)
	}
	newPres := base64.RawURLEncoding.EncodeToString(newRefresh)
	newHash := sha256.Sum256([]byte(newPres))
	newID, err := uuid.NewV7()
	if err != nil {
		return RefreshOutcomeUnknown, nil, fmt.Errorf("identity: uuid: %w", err)
	}
	// Carry the original absolute deadline UNCHANGED onto the rotated row.
	if _, err := tx.Exec(ctx, `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, absolute_expires_at, session_id)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		newID, userID, newHash[:], time.Now().UTC().Add(RefreshTokenWindow), absoluteExp, sessionID,
	); err != nil {
		return RefreshOutcomeUnknown, nil, fmt.Errorf("identity: insert rotated refresh: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE refresh_tokens SET rotated_to_id = $1 WHERE id = $2`,
		newID, rowID,
	); err != nil {
		return RefreshOutcomeUnknown, nil, fmt.Errorf("identity: mark rotation: %w", err)
	}

	boundSession := uuid.Nil
	if sessionID != nil {
		boundSession = *sessionID
	}
	access, claims, err := IssueJWTForSession(userID, role, boundSession)
	if err != nil {
		return RefreshOutcomeUnknown, nil, err
	}
	pair := &TokenPair{AccessToken: access, RefreshToken: newPres, Claims: claims, SessionID: boundSession, NewRefreshID: newID}
	if absoluteExp != nil {
		pair.AbsoluteExpiresAt = *absoluteExp
	}
	return RefreshRotated, pair, nil
}

// ConsumeRefreshToken is the pool-level wrapper: it owns a transaction,
// calls ConsumeRefreshTokenTx and commits when the outcome wrote
// something durable. Kept for callers with no transaction of their own.
// The interactive handlers do NOT use it: they own the transaction so
// the rotation commits with the credentials it produced.
func ConsumeRefreshToken(ctx context.Context, pool *pgxpool.Pool, token, role string) (*TokenPair, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity: refresh begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	outcome, pair, err := ConsumeRefreshTokenTx(ctx, tx, token, role)
	if err != nil {
		return nil, err
	}
	if outcome.MustCommit() {
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("identity: refresh commit: %w", err)
		}
		committed = true
	}
	if outcome != RefreshRotated {
		return nil, outcome.Err()
	}
	return pair, nil
}

// UserIDForRefreshToken resolves the owner of a presented refresh token
// WITHOUT consuming it, so a handler can take the per-user lock before
// it touches the chain. Validity is decided inside the locked
// transaction by ConsumeRefreshTokenTx.
func UserIDForRefreshToken(ctx context.Context, db DBTX, token string) (uuid.UUID, error) {
	if token == "" {
		return uuid.Nil, ErrRefreshTokenNotFound
	}
	hash := sha256.Sum256([]byte(token))
	var userID uuid.UUID
	err := db.QueryRow(ctx,
		`SELECT user_id FROM refresh_tokens WHERE token_hash = $1`, hash[:]).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrRefreshTokenNotFound
		}
		return uuid.Nil, fmt.Errorf("identity: refresh owner lookup: %w", err)
	}
	return userID, nil
}

// RebindRefreshToSession points a refresh row at a different session.
// The cookie-refresh path mints a NEW session on every rotation, so the
// row it just created must follow, or the lineage would stay bound to a
// session that no longer backs it. Runs in the caller's transaction.
// Spec C-38.
func RebindRefreshToSession(ctx context.Context, db DBTX, refreshID, sessionID uuid.UUID) error {
	if refreshID == uuid.Nil || sessionID == uuid.Nil {
		return nil
	}
	if _, err := db.Exec(ctx,
		`UPDATE refresh_tokens SET session_id = $1 WHERE id = $2`, sessionID, refreshID); err != nil {
		return fmt.Errorf("identity: rebind refresh to session: %w", err)
	}
	return nil
}
