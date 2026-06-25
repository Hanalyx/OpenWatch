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
func RevokeRefreshToken(ctx context.Context, pool *pgxpool.Pool, token string) error {
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
func IssueRefreshToken(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, absoluteExpiresAt time.Time) (token string, err error) {
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
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, absolute_expires_at)
		VALUES ($1, $2, $3, $4, $5)`
	if _, err := pool.Exec(ctx, stmt, id, userID, hash[:],
		time.Now().UTC().Add(RefreshTokenWindow), nullableTime(absoluteExpiresAt)); err != nil {
		return "", fmt.Errorf("identity: insert refresh: %w", err)
	}
	return token, nil
}

// nullableTime returns nil for the zero time (stored as SQL NULL) or the time
// otherwise — so a missing absolute deadline is recorded honestly as "none".
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
}

// ConsumeRefreshToken atomically:
//  1. Looks up the row by presentation-token hash.
//  2. Validates not-revoked, not-expired, not-already-rotated.
//  3. If already rotated: sets reuse_detected_at, revokes ALL sessions
//     for the user, returns ErrRefreshTokenReused.
//  4. Otherwise: mints a new (access, refresh) pair, marks the old row
//     as rotated to the new one (atomic via single UPDATE), returns
//     the new pair.
//
// Spec AC-12, AC-13.
func ConsumeRefreshToken(ctx context.Context, pool *pgxpool.Pool, token, role string) (*TokenPair, error) {
	if token == "" {
		return nil, ErrRefreshTokenNotFound
	}
	hash := sha256.Sum256([]byte(token))

	// All work in one transaction so reuse detection + cascade revoke
	// is atomic with the rotation.
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("identity: refresh begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		rowID       uuid.UUID
		userID      uuid.UUID
		expiresAt   time.Time
		absoluteExp *time.Time
		rotatedTo   *uuid.UUID
		revokedAt   *time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT id, user_id, expires_at, absolute_expires_at, rotated_to_id, revoked_at
		FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`,
		hash[:],
	).Scan(&rowID, &userID, &expiresAt, &absoluteExp, &rotatedTo, &revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("identity: refresh lookup: %w", err)
	}

	if revokedAt != nil {
		return nil, ErrRefreshTokenRevoked
	}
	if time.Now().UTC().After(expiresAt) {
		return nil, ErrRefreshTokenExpired
	}
	// AUTH-1 (b): the session's absolute deadline is a hard ceiling. Once it
	// passes, the chain ends even though the 7-day refresh window is still
	// open. Legacy tokens (absolute_expires_at NULL) are exempt until they age
	// out. Checked before reuse so an expired-session token simply fails closed.
	if absoluteExp != nil && time.Now().UTC().After(*absoluteExp) {
		return nil, ErrRefreshSessionExpired
	}
	if rotatedTo != nil {
		// Reuse! This row was already consumed. An attacker has the old
		// presentation token. Revoke everything for this user.
		if _, err := tx.Exec(ctx,
			`UPDATE refresh_tokens SET reuse_detected_at = now() WHERE id = $1`,
			rowID); err != nil {
			return nil, fmt.Errorf("identity: mark reuse: %w", err)
		}
		// Cascade: revoke every active refresh token AND every active
		// session for this user.
		if _, err := tx.Exec(ctx,
			`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
			userID); err != nil {
			return nil, fmt.Errorf("identity: cascade revoke refresh: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
			userID); err != nil {
			return nil, fmt.Errorf("identity: cascade revoke sessions: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("identity: refresh commit (reuse): %w", err)
		}
		return nil, ErrRefreshTokenReused
	}

	// Happy path: mint a new pair, rotate the old row's pointer.
	newRefresh := make([]byte, 32)
	if _, err := rand.Read(newRefresh); err != nil {
		return nil, fmt.Errorf("identity: refresh entropy: %w", err)
	}
	newPres := base64.RawURLEncoding.EncodeToString(newRefresh)
	newHash := sha256.Sum256([]byte(newPres))
	newID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("identity: uuid: %w", err)
	}
	// Carry the original absolute deadline UNCHANGED onto the rotated row, so
	// the absolute ceiling cannot be reset by refreshing (AUTH-1 b).
	if _, err := tx.Exec(ctx, `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, absolute_expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		newID, userID, newHash[:], time.Now().UTC().Add(RefreshTokenWindow), absoluteExp,
	); err != nil {
		return nil, fmt.Errorf("identity: insert rotated refresh: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE refresh_tokens SET rotated_to_id = $1 WHERE id = $2`,
		newID, rowID,
	); err != nil {
		return nil, fmt.Errorf("identity: mark rotation: %w", err)
	}

	access, claims, err := IssueJWT(userID, role)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("identity: refresh commit (happy): %w", err)
	}
	pair := &TokenPair{
		AccessToken:  access,
		RefreshToken: newPres,
		Claims:       claims,
	}
	if absoluteExp != nil {
		pair.AbsoluteExpiresAt = *absoluteExp
	}
	return pair, nil
}
