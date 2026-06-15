package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrChannelNotFound is returned when a channel id does not exist.
var ErrChannelNotFound = errors.New("notification: channel not found")

// ErrInvalidConfig is returned when create/update validation fails.
var ErrInvalidConfig = errors.New("notification: invalid channel config")

// Service is the notification-channel CRUD entry point. Secrets are
// encrypted with the active data key on write and decrypted only on the
// delivery/test paths.
type Service struct {
	pool *pgxpool.Pool
}

// NewService binds a Service to a DB pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// validate checks type, name, and the target URL. It returns the
// non-secret display host (target_hint) on success. The host syntactic +
// literal-IP SSRF check happens here; the dial-time guard in delivery.go
// re-checks after DNS to close the TOCTOU gap.
func validate(typ ChannelType, name string, cfg Config) (string, error) {
	if !typ.IsValid() {
		return "", fmt.Errorf("%w: unknown type %q", ErrInvalidConfig, typ)
	}
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%w: name required", ErrInvalidConfig)
	}
	if typ == TypeEmail {
		return validateEmail(cfg)
	}
	return safeURLHost(cfg.URL)
}

// validateEmail checks the SMTP config and returns the host as the
// non-secret target_hint. The relay host is NOT SSRF-restricted (internal
// mail relays are legitimate); TLS + auth protect the credential.
func validateEmail(cfg Config) (string, error) {
	host := strings.TrimSpace(cfg.SMTPHost)
	if host == "" {
		return "", fmt.Errorf("%w: smtp host required", ErrInvalidConfig)
	}
	if cfg.SMTPPort <= 0 || cfg.SMTPPort > 65535 {
		return "", fmt.Errorf("%w: smtp port out of range", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.From) == "" {
		return "", fmt.Errorf("%w: from address required", ErrInvalidConfig)
	}
	if len(cfg.To) == 0 {
		return "", fmt.Errorf("%w: at least one recipient required", ErrInvalidConfig)
	}
	return host, nil
}

// safeURLHost parses raw, requires an https URL to a non-private host,
// and returns the host for display. Literal private/loopback/link-local
// IPs are rejected up front (SSRF). DNS names are re-resolved and checked
// at dial time.
func safeURLHost(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%w: unparseable url", ErrInvalidConfig)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("%w: url must be https", ErrInvalidConfig)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("%w: url has no host", ErrInvalidConfig)
	}
	if isBlockedHost(host) {
		return "", fmt.Errorf("%w: url host is not allowed", ErrInvalidConfig)
	}
	return host, nil
}

// Create persists a new channel, encrypting its config.
func (s *Service) Create(ctx context.Context, p CreateParams) (Channel, error) {
	hint, err := validate(p.Type, p.Name, p.Config)
	if err != nil {
		return Channel{}, err
	}
	cipher, err := encryptConfig(p.Config)
	if err != nil {
		return Channel{}, err
	}
	tags, err := json.Marshal(nonNilTags(p.TagFilter))
	if err != nil {
		return Channel{}, fmt.Errorf("notification: marshal tags: %w", err)
	}
	const stmt = `
		INSERT INTO notification_channels (type, name, enabled, config_ciphertext, target_hint, tag_filter)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`
	var c Channel
	if err := s.pool.QueryRow(ctx, stmt,
		string(p.Type), p.Name, p.Enabled, cipher, hint, tags,
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return Channel{}, fmt.Errorf("notification: insert: %w", err)
	}
	c.Type = p.Type
	c.Name = p.Name
	c.Enabled = p.Enabled
	c.TargetHint = hint
	c.TagFilter = nonNilTags(p.TagFilter)
	return c, nil
}

// List returns all channels without secrets (Config zero).
func (s *Service) List(ctx context.Context) ([]Channel, error) {
	const stmt = `
		SELECT id, type, name, enabled, target_hint, tag_filter, created_at, updated_at
		FROM notification_channels
		ORDER BY created_at ASC`
	rows, err := s.pool.Query(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("notification: list: %w", err)
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		c, err := scanMeta(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Get returns a single channel without its secret.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Channel, error) {
	const stmt = `
		SELECT id, type, name, enabled, target_hint, tag_filter, created_at, updated_at
		FROM notification_channels WHERE id = $1`
	c, err := scanMeta(s.pool.QueryRow(ctx, stmt, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Channel{}, ErrChannelNotFound
		}
		return Channel{}, err
	}
	return c, nil
}

// getDecrypted returns a channel WITH its decrypted Config. Internal:
// only the delivery + test paths use it.
func (s *Service) getDecrypted(ctx context.Context, id uuid.UUID) (Channel, error) {
	const stmt = `
		SELECT id, type, name, enabled, target_hint, tag_filter, config_ciphertext, created_at, updated_at
		FROM notification_channels WHERE id = $1`
	var (
		c      Channel
		typ    string
		tags   []byte
		cipher []byte
	)
	err := s.pool.QueryRow(ctx, stmt, id).Scan(
		&c.ID, &typ, &c.Name, &c.Enabled, &c.TargetHint, &tags, &cipher, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Channel{}, ErrChannelNotFound
		}
		return Channel{}, fmt.Errorf("notification: get: %w", err)
	}
	c.Type = ChannelType(typ)
	if err := json.Unmarshal(tags, &c.TagFilter); err != nil {
		return Channel{}, fmt.Errorf("notification: unmarshal tags: %w", err)
	}
	cfg, err := decryptConfig(cipher)
	if err != nil {
		return Channel{}, err
	}
	c.Config = cfg
	return c, nil
}

// Update mutates name/enabled/tag_filter, and the secret config only when
// ReplaceConfig is set.
func (s *Service) Update(ctx context.Context, id uuid.UUID, p UpdateParams) (Channel, error) {
	// Fetch the existing channel for the 404 path and its (immutable) type,
	// which selects how a replacement config is validated.
	existing, err := s.Get(ctx, id)
	if err != nil {
		return Channel{}, err
	}
	if strings.TrimSpace(p.Name) == "" {
		return Channel{}, fmt.Errorf("%w: name required", ErrInvalidConfig)
	}
	tags, err := json.Marshal(nonNilTags(p.TagFilter))
	if err != nil {
		return Channel{}, fmt.Errorf("notification: marshal tags: %w", err)
	}
	if p.ReplaceConfig {
		hint, vErr := validate(existing.Type, p.Name, p.Config)
		if vErr != nil {
			return Channel{}, vErr
		}
		cipher, eErr := encryptConfig(p.Config)
		if eErr != nil {
			return Channel{}, eErr
		}
		const stmt = `
			UPDATE notification_channels
			SET name=$2, enabled=$3, tag_filter=$4, config_ciphertext=$5, target_hint=$6, updated_at=now()
			WHERE id=$1`
		if _, err := s.pool.Exec(ctx, stmt, id, p.Name, p.Enabled, tags, cipher, hint); err != nil {
			return Channel{}, fmt.Errorf("notification: update: %w", err)
		}
	} else {
		const stmt = `
			UPDATE notification_channels
			SET name=$2, enabled=$3, tag_filter=$4, updated_at=now()
			WHERE id=$1`
		if _, err := s.pool.Exec(ctx, stmt, id, p.Name, p.Enabled, tags); err != nil {
			return Channel{}, fmt.Errorf("notification: update: %w", err)
		}
	}
	return s.Get(ctx, id)
}

// Delete removes a channel. Idempotent for a missing id.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM notification_channels WHERE id=$1`, id); err != nil {
		return fmt.Errorf("notification: delete: %w", err)
	}
	return nil
}

// listEnabledDecrypted returns enabled channels with decrypted configs,
// for the dispatch fan-out.
func (s *Service) listEnabledDecrypted(ctx context.Context) ([]Channel, error) {
	const stmt = `
		SELECT id, type, name, enabled, target_hint, tag_filter, config_ciphertext, created_at, updated_at
		FROM notification_channels WHERE enabled = true ORDER BY created_at ASC`
	rows, err := s.pool.Query(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("notification: list enabled: %w", err)
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		var (
			c      Channel
			typ    string
			tags   []byte
			cipher []byte
		)
		if err := rows.Scan(&c.ID, &typ, &c.Name, &c.Enabled, &c.TargetHint, &tags, &cipher,
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("notification: scan enabled: %w", err)
		}
		c.Type = ChannelType(typ)
		_ = json.Unmarshal(tags, &c.TagFilter)
		cfg, err := decryptConfig(cipher)
		if err != nil {
			return nil, err
		}
		c.Config = cfg
		out = append(out, c)
	}
	return out, rows.Err()
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanMeta scans the non-secret columns into a Channel.
func scanMeta(row rowScanner) (Channel, error) {
	var (
		c    Channel
		typ  string
		tags []byte
	)
	if err := row.Scan(&c.ID, &typ, &c.Name, &c.Enabled, &c.TargetHint, &tags,
		&c.CreatedAt, &c.UpdatedAt); err != nil {
		return Channel{}, err
	}
	c.Type = ChannelType(typ)
	if err := json.Unmarshal(tags, &c.TagFilter); err != nil {
		return Channel{}, fmt.Errorf("notification: unmarshal tags: %w", err)
	}
	return c, nil
}

func encryptConfig(cfg Config) ([]byte, error) {
	dek, err := secretkey.Active()
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("notification: marshal config: %w", err)
	}
	cipher, err := dek.Encrypt(plain)
	if err != nil {
		return nil, fmt.Errorf("notification: encrypt config: %w", err)
	}
	return cipher, nil
}

func decryptConfig(cipher []byte) (Config, error) {
	dek, err := secretkey.Active()
	if err != nil {
		return Config{}, err
	}
	plain, err := dek.Decrypt(cipher)
	if err != nil {
		return Config{}, fmt.Errorf("notification: decrypt config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return Config{}, fmt.Errorf("notification: unmarshal config: %w", err)
	}
	return cfg, nil
}

func nonNilTags(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
