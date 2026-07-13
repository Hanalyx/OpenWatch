package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// MFA lifecycle errors. Identity binder + login handler translate to
// auth.mfa.failed audit reasons.
var (
	ErrMFANotEnrolled = errors.New("identity: mfa not enrolled for user")
	ErrMFAInvalidOTP  = errors.New("identity: mfa otp invalid or out of window")
	ErrOTPReplayed    = errors.New("identity: mfa otp already used inside replay window")
)

// TOTPIssuer is the human-facing label baked into provisioning URIs.
// Authenticator apps display this above the username.
const TOTPIssuer = "OpenWatch"

// TOTPSecretBytes is the entropy of the per-user shared secret. RFC 4226
// requires ≥80 bits; NIST SP 800-63B requires ≥128. Spec C-09 sets 160.
const TOTPSecretBytes = 20 // 160 bits

// OTPReplayWindow is how long a used OTP value remains in the replay-
// prevention table. Set to twice the validation window (±1 step = 90s
// validation, so 180s replay protection covers the boundary).
const OTPReplayWindow = 180 * time.Second

// SetEphemeralMFAKey installs a random key. Tests and dev mode only.
// Wrapper over secretkey.SetEphemeral.
//
// Deprecated: use secretkey.SetEphemeral instead.
func SetEphemeralMFAKey() error { return secretkey.SetEphemeral() }

// EnrollMFA generates a fresh 160-bit secret, stores it AES-256-GCM
// encrypted via the shared secretkey package, and returns the
// provisioning URI for an authenticator app.
//
// Spec AC-14, C-09.
func EnrollMFA(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, username string) (provisioningURI string, err error) {
	dek, err := secretkey.Active()
	if err != nil {
		return "", err
	}

	// Use pquerna/otp to generate the secret + URI in one call so the
	// secret format matches what authenticator apps expect.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: username,
		SecretSize:  TOTPSecretBytes,
		Algorithm:   otp.AlgorithmSHA1, // most authenticator apps default to SHA1
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return "", fmt.Errorf("identity: generate totp: %w", err)
	}

	enc, err := dek.Encrypt([]byte(key.Secret()))
	if err != nil {
		return "", err
	}
	// Upsert — re-enrolling overwrites. The user MUST re-pair their app.
	const stmt = `
		INSERT INTO auth_mfa_secrets (user_id, encrypted_secret, enrolled_at)
		VALUES ($1, $2, now())
		ON CONFLICT (user_id) DO UPDATE SET encrypted_secret = EXCLUDED.encrypted_secret,
		                                   enrolled_at      = now(),
		                                   last_verified_at = NULL`
	if _, err := pool.Exec(ctx, stmt, userID, enc); err != nil {
		return "", fmt.Errorf("identity: persist mfa secret: %w", err)
	}
	return key.URL(), nil
}

// VerifyMFA validates an OTP against the user's enrolled secret. Returns:
//   - ErrMFANotEnrolled if no secret exists for the user
//   - ErrOTPReplayed if the same OTP was used within OTPReplayWindow
//   - ErrMFAInvalidOTP if the OTP is outside the ±1 step window
//   - nil on success
//
// Replay protection: each successful verify stores (user_id, otp) in
// auth_mfa_otp_uses for OTPReplayWindow seconds. A second use within
// that window fails — even if the OTP is still inside the ±1 step
// validation window.
//
// Spec AC-15, AC-16, C-10.
func VerifyMFA(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, otpValue string) error {
	dek, err := secretkey.Active()
	if err != nil {
		return err
	}
	var enc []byte
	err = pool.QueryRow(ctx,
		`SELECT encrypted_secret FROM auth_mfa_secrets WHERE user_id = $1`,
		userID,
	).Scan(&enc)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("identity: lookup mfa secret: %w", err)
	}
	secret, err := dek.Decrypt(enc)
	if err != nil {
		return fmt.Errorf("identity: decrypt mfa secret: %w", err)
	}

	// totp.ValidateCustom locks the parameters exactly. Skew=1 = ±1 step.
	valid, err := totp.ValidateCustom(otpValue, string(secret), time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return fmt.Errorf("identity: validate otp: %w", err)
	}
	if !valid {
		return ErrMFAInvalidOTP
	}

	// Replay check.
	const stmt = `
		INSERT INTO auth_mfa_otp_uses (user_id, otp, used_at)
		VALUES ($1, $2, now())
		ON CONFLICT (user_id, otp) DO NOTHING
		RETURNING user_id`
	var firstUse uuid.UUID
	err = pool.QueryRow(ctx, stmt, userID, otpValue).Scan(&firstUse)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOTPReplayed
	}
	if err != nil {
		return fmt.Errorf("identity: mark otp used: %w", err)
	}

	// Best-effort: touch last_verified_at. Non-fatal.
	_, _ = pool.Exec(ctx,
		`UPDATE auth_mfa_secrets SET last_verified_at = now() WHERE user_id = $1`,
		userID)
	return nil
}

// PurgeStaleOTPs deletes OTP-use rows older than OTPReplayWindow. Called
// by a cron tick.
func PurgeStaleOTPs(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx,
		`DELETE FROM auth_mfa_otp_uses WHERE used_at < now() - interval '180 seconds'`)
	if err != nil {
		return 0, fmt.Errorf("identity: purge otps: %w", err)
	}
	return tag.RowsAffected(), nil
}
