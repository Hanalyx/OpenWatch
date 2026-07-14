// Package host owns the hosts table — the inventory of machines the
// platform can talk to. CRUD only; OS discovery and monitoring state
// land in later slices when their producers exist.
//
// Spec: app/specs/system/host-inventory.spec.yaml.
package host

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service errors.
var (
	ErrHostNotFound   = errors.New("host: not found")
	ErrInvalidHost    = errors.New("host: invalid input")
	ErrDuplicateHost  = errors.New("host: hostname already exists in this environment")
	ErrInvalidCreator = errors.New("host: created_by user does not exist")
	ErrInvalidTarget  = errors.New("host: target_framework is too long or has invalid characters")
)

// Host is the safe shape returned by every read API.
type Host struct {
	ID          uuid.UUID
	Hostname    string
	IPAddress   string
	Port        int
	DisplayName string
	Description string
	Environment string
	Tags        []string
	GroupID     *uuid.UUID
	Username    string // per-host override; empty = fall back to system default
	CreatedBy   uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time

	// v1.3.0 — multi-layer adaptive health-check fields. Default to
	// false / 3 on rows that pre-date migration 0016.
	MaintenanceMode bool
	CheckPriority   int

	// v1.4.0 — denormalized OS fields populated by system-host-discovery
	// via migration 0017. All nil pre-Discovery.
	OSFamily           *string
	OSVersion          *string
	Architecture       *string
	PlatformIdentifier *string
	OSDiscoveredAt     *time.Time

	// Phase 3 (compliance-targets) — the host's own durable target
	// framework: operator intent about which framework family this host is
	// held to (its default lens, and the per-host override that wins over
	// any site-group target in host_effective_target). nil = inherit
	// (site-group target, else the org default). Set via SetTarget; read
	// by GetByID/UpdateHost. Spec system-compliance-lens, api-hosts.
	TargetFramework *string
}

// CreateParams is the input to CreateHost. Validation enforces the
// "no empty hostname/ip" rule before the SQL would reject it on NOT NULL.
type CreateParams struct {
	Hostname    string
	IPAddress   string
	Port        int // 0 → default 22
	DisplayName string
	Description string
	Environment string // empty → "production"
	Tags        []string
	GroupID     *uuid.UUID
	Username    string
	CreatedBy   uuid.UUID
}

// UpdateParams carries the patch fields for UpdateHost. Pointers
// distinguish "leave unchanged" (nil) from "set to value." String
// fields with no business meaning are pointers; required fields stay
// as plain types because they cannot be unset.
type UpdateParams struct {
	IPAddress   *string
	Port        *int
	DisplayName *string
	Description *string
	Environment *string
	Tags        *[]string
	GroupID     *uuid.UUID
	Username    *string
}

// ListParams scopes List. Empty fields = no filter on that axis.
type ListParams struct {
	Environment string
	Tag         string
}

// Service is the host CRUD entry point.
type Service struct {
	pool *pgxpool.Pool
}

// NewService binds a Service to a DB pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// CreateHost validates input, inserts the row, returns the new Host.
//
// Spec AC-03, AC-04, AC-05.
func (s *Service) CreateHost(ctx context.Context, p CreateParams) (Host, error) {
	if strings.TrimSpace(p.Hostname) == "" {
		return Host{}, ErrInvalidHost
	}
	if strings.TrimSpace(p.IPAddress) == "" || net.ParseIP(p.IPAddress) == nil {
		return Host{}, ErrInvalidHost
	}
	if p.Port == 0 {
		p.Port = 22
	}
	if p.Port < 1 || p.Port > 65535 {
		return Host{}, ErrInvalidHost
	}
	if p.Environment == "" {
		p.Environment = "production"
	}
	if p.Tags == nil {
		p.Tags = []string{}
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Host{}, fmt.Errorf("host: uuid: %w", err)
	}
	const stmt = `
		INSERT INTO hosts (id, hostname, ip_address, port, display_name, description,
		                   environment, tags, group_id, username, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, hostname, host(ip_address), port,
		          COALESCE(display_name, ''), COALESCE(description, ''),
		          environment, tags, group_id, COALESCE(username, ''),
		          created_by, created_at, updated_at,
		          maintenance_mode, check_priority,
		          os_family, os_version, architecture, platform_identifier, os_discovered_at`
	var h Host
	err = s.pool.QueryRow(ctx, stmt,
		id, p.Hostname, p.IPAddress, p.Port,
		nilIfEmpty(p.DisplayName), nilIfEmpty(p.Description),
		p.Environment, p.Tags, p.GroupID, nilIfEmpty(p.Username), p.CreatedBy,
	).Scan(
		&h.ID, &h.Hostname, &h.IPAddress, &h.Port,
		&h.DisplayName, &h.Description,
		&h.Environment, &h.Tags, &h.GroupID, &h.Username,
		&h.CreatedBy, &h.CreatedAt, &h.UpdatedAt,
		&h.MaintenanceMode, &h.CheckPriority,
		&h.OSFamily, &h.OSVersion, &h.Architecture, &h.PlatformIdentifier, &h.OSDiscoveredAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Host{}, ErrDuplicateHost
		}
		if isFKViolation(err) {
			return Host{}, ErrInvalidCreator
		}
		return Host{}, fmt.Errorf("host: insert: %w", err)
	}

	// Seed the adaptive-scan schedule row: state unknown, due
	// immediately (column default next_scheduled_scan = now()), so a
	// fresh host gets its first compliance scan on the next scheduler
	// tick without anyone clicking. Best-effort: a failure here never
	// fails host creation — the migration backfill (0024) and
	// ON CONFLICT keep this idempotent and self-healing.
	// Spec system-scheduler v3.0.0 (seeding half of AC-08).
	if _, seedErr := s.pool.Exec(ctx, `
		INSERT INTO host_compliance_schedule (host_id)
		VALUES ($1) ON CONFLICT (host_id) DO NOTHING`, h.ID); seedErr != nil {
		slog.WarnContext(ctx, "host: seed compliance schedule failed",
			slog.String("host_id", h.ID.String()),
			slog.String("error", seedErr.Error()))
	}
	return h, nil
}

// GetByID returns the host when active; ErrHostNotFound for unknown
// or soft-deleted IDs.
//
// Spec AC-07.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (Host, error) {
	const stmt = `
		SELECT id, hostname, host(ip_address), port,
		       COALESCE(display_name, ''), COALESCE(description, ''),
		       environment, tags, group_id, COALESCE(username, ''),
		       created_by, created_at, updated_at,
		       maintenance_mode, check_priority,
		       os_family, os_version, architecture, platform_identifier, os_discovered_at,
		       target_framework
		FROM hosts WHERE id = $1 AND deleted_at IS NULL`
	var h Host
	err := s.pool.QueryRow(ctx, stmt, id).Scan(
		&h.ID, &h.Hostname, &h.IPAddress, &h.Port,
		&h.DisplayName, &h.Description,
		&h.Environment, &h.Tags, &h.GroupID, &h.Username,
		&h.CreatedBy, &h.CreatedAt, &h.UpdatedAt,
		&h.MaintenanceMode, &h.CheckPriority,
		&h.OSFamily, &h.OSVersion, &h.Architecture, &h.PlatformIdentifier, &h.OSDiscoveredAt,
		&h.TargetFramework,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Host{}, ErrHostNotFound
		}
		return Host{}, fmt.Errorf("host: query: %w", err)
	}
	return h, nil
}

// SetTarget sets (or clears, when family is "") the host's own compliance
// target framework. This is the per-host override: in host_effective_target it
// wins over any site-group target. Unlike a group target there is no site-only
// constraint (D1) — a host may always carry its own target. The family token is
// resolved leniently against the live corpus at query time, so this only
// bounds garbage/length (D3 handles a target with no matching corpus key as
// N/A, not 0%). Spec system-compliance-lens, api-hosts.
func (s *Service) SetTarget(ctx context.Context, id uuid.UUID, family string) (Host, error) {
	if !validTargetFramework(family) {
		return Host{}, ErrInvalidTarget
	}
	var arg *string
	if family != "" {
		arg = &family
	}
	const stmt = `
		UPDATE hosts SET target_framework = $2, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING id, hostname, host(ip_address), port,
		          COALESCE(display_name, ''), COALESCE(description, ''),
		          environment, tags, group_id, COALESCE(username, ''),
		          created_by, created_at, updated_at,
		          maintenance_mode, check_priority,
		          os_family, os_version, architecture, platform_identifier, os_discovered_at,
		          target_framework`
	var h Host
	err := s.pool.QueryRow(ctx, stmt, id, arg).Scan(
		&h.ID, &h.Hostname, &h.IPAddress, &h.Port,
		&h.DisplayName, &h.Description,
		&h.Environment, &h.Tags, &h.GroupID, &h.Username,
		&h.CreatedBy, &h.CreatedAt, &h.UpdatedAt,
		&h.MaintenanceMode, &h.CheckPriority,
		&h.OSFamily, &h.OSVersion, &h.Architecture, &h.PlatformIdentifier, &h.OSDiscoveredAt,
		&h.TargetFramework,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Host{}, ErrHostNotFound
		}
		return Host{}, fmt.Errorf("host: set target: %w", err)
	}
	return h, nil
}

// validTargetFramework bounds a compliance-target family token: empty (clear)
// or <=64 chars of lowercase alnum plus _-. It mirrors the group service's
// validator; the token is resolved leniently against the live corpus at query
// time, so this only blocks garbage / length.
func validTargetFramework(f string) bool {
	if len(f) > 64 {
		return false
	}
	for _, r := range f {
		if !(r == '_' || r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// UpdateHost applies the supplied patch fields and bumps updated_at.
// Immutable fields (id, created_by, created_at) are preserved per spec AC-08.
func (s *Service) UpdateHost(ctx context.Context, id uuid.UUID, p UpdateParams) (Host, error) {
	// Build the SET clause dynamically. Skip fields where the caller
	// passed nil ("leave unchanged"). Build a parameter list in parallel
	// to keep the placeholders aligned.
	sets := []string{}
	args := []any{}
	add := func(col string, val any) {
		args = append(args, val)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if p.IPAddress != nil {
		if net.ParseIP(*p.IPAddress) == nil {
			return Host{}, ErrInvalidHost
		}
		add("ip_address", *p.IPAddress)
	}
	if p.Port != nil {
		if *p.Port < 1 || *p.Port > 65535 {
			return Host{}, ErrInvalidHost
		}
		add("port", *p.Port)
	}
	if p.DisplayName != nil {
		add("display_name", nilIfEmpty(*p.DisplayName))
	}
	if p.Description != nil {
		add("description", nilIfEmpty(*p.Description))
	}
	if p.Environment != nil {
		if *p.Environment == "" {
			return Host{}, ErrInvalidHost
		}
		add("environment", *p.Environment)
	}
	if p.Tags != nil {
		add("tags", *p.Tags)
	}
	if p.GroupID != nil {
		add("group_id", *p.GroupID)
	}
	if p.Username != nil {
		add("username", nilIfEmpty(*p.Username))
	}
	if len(sets) == 0 {
		return s.GetByID(ctx, id)
	}
	// Always bump updated_at.
	sets = append(sets, "updated_at = now()")
	args = append(args, id)
	idPlaceholder := len(args)

	stmt := fmt.Sprintf(`
		UPDATE hosts SET %s
		WHERE id = $%d AND deleted_at IS NULL
		RETURNING id, hostname, host(ip_address), port,
		          COALESCE(display_name, ''), COALESCE(description, ''),
		          environment, tags, group_id, COALESCE(username, ''),
		          created_by, created_at, updated_at,
		          maintenance_mode, check_priority,
		          os_family, os_version, architecture, platform_identifier, os_discovered_at,
		          target_framework`,
		strings.Join(sets, ", "), idPlaceholder)

	var h Host
	err := s.pool.QueryRow(ctx, stmt, args...).Scan(
		&h.ID, &h.Hostname, &h.IPAddress, &h.Port,
		&h.DisplayName, &h.Description,
		&h.Environment, &h.Tags, &h.GroupID, &h.Username,
		&h.CreatedBy, &h.CreatedAt, &h.UpdatedAt,
		&h.MaintenanceMode, &h.CheckPriority,
		&h.OSFamily, &h.OSVersion, &h.Architecture, &h.PlatformIdentifier, &h.OSDiscoveredAt,
		&h.TargetFramework,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Host{}, ErrHostNotFound
		}
		if isUniqueViolation(err) {
			return Host{}, ErrDuplicateHost
		}
		return Host{}, fmt.Errorf("host: update: %w", err)
	}
	return h, nil
}

// SoftDelete sets deleted_at; subsequent lookups return ErrHostNotFound.
// The row remains physically present for audit forensics.
//
// Spec AC-12, C-03.
func (s *Service) SoftDelete(ctx context.Context, id uuid.UUID) error {
	const stmt = `UPDATE hosts SET deleted_at = now(), updated_at = now()
	              WHERE id = $1 AND deleted_at IS NULL`
	tag, err := s.pool.Exec(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("host: soft delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrHostNotFound
	}
	return nil
}

// List returns active hosts matching the filter. Empty Environment +
// empty Tag returns all active hosts.
//
// Spec AC-09, AC-10, AC-11.
func (s *Service) List(ctx context.Context, p ListParams) ([]Host, error) {
	clauses := []string{"deleted_at IS NULL"}
	args := []any{}
	if p.Environment != "" {
		args = append(args, p.Environment)
		clauses = append(clauses, fmt.Sprintf("environment = $%d", len(args)))
	}
	if p.Tag != "" {
		args = append(args, p.Tag)
		clauses = append(clauses, fmt.Sprintf("$%d = ANY(tags)", len(args)))
	}
	stmt := fmt.Sprintf(`
		SELECT id, hostname, host(ip_address), port,
		       COALESCE(display_name, ''), COALESCE(description, ''),
		       environment, tags, group_id, COALESCE(username, ''),
		       created_by, created_at, updated_at,
		       maintenance_mode, check_priority,
		       os_family, os_version, architecture, platform_identifier, os_discovered_at
		FROM hosts WHERE %s ORDER BY created_at DESC`, strings.Join(clauses, " AND "))

	rows, err := s.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("host: list: %w", err)
	}
	defer rows.Close()
	out := []Host{}
	for rows.Next() {
		var h Host
		if err := rows.Scan(
			&h.ID, &h.Hostname, &h.IPAddress, &h.Port,
			&h.DisplayName, &h.Description,
			&h.Environment, &h.Tags, &h.GroupID, &h.Username,
			&h.CreatedBy, &h.CreatedAt, &h.UpdatedAt,
			&h.MaintenanceMode, &h.CheckPriority,
			&h.OSFamily, &h.OSVersion, &h.Architecture, &h.PlatformIdentifier, &h.OSDiscoveredAt,
		); err != nil {
			return nil, fmt.Errorf("host: scan: %w", err)
		}
		out = append(out, h)
	}
	return out, nil
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

func isFKViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23503"
	}
	return false
}
