package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SSHTransport is the seam the collector uses for SSH I/O. Same shape
// as discovery.SSHTransport; duplicated here so collector doesn't
// import discovery (which would import internal/credential — fine in
// production, but avoiding cross-imports between sibling intelligence
// subpackages keeps the dependency graph readable).
type SSHTransport interface {
	Dial(ctx context.Context, host string, port int, cred *credential.Credential) (SSHSession, error)
}

// SSHSession is one live session against a remote host.
type SSHSession interface {
	Run(ctx context.Context, cmd string) (stdout []byte, exitCode int, err error)
	Close() error
}

// HostLookup is the seam for reading host connection facts. Production
// uses an adapter over pgxpool; tests stub directly.
type HostLookup interface {
	GetForIntelligence(ctx context.Context, hostID uuid.UUID) (Addr, error)
}

// Addr is the host:port tuple.
type Addr struct {
	Host string
	Port int
}

// AuditEmitFunc is the audit emission seam.
type AuditEmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// Publisher is the eventbus subset used by collector. *eventbus.Bus
// satisfies it; tests inject a recorder.
type Publisher interface {
	Publish(ctx context.Context, event eventbus.Event)
}

// Service is the OS Intelligence collector. Construct via NewService.
type Service struct {
	pool      *pgxpool.Pool
	credSvc   *credential.Service
	emit      AuditEmitFunc
	bus       Publisher
	lookup    HostLookup
	transport SSHTransport
}

// NewService constructs a Service. emit + bus may be nil — RunCycle
// degrades gracefully (skips audit / publish on nil).
func NewService(pool *pgxpool.Pool, emit AuditEmitFunc, bus Publisher) *Service {
	return &Service{pool: pool, emit: emit, bus: bus}
}

// WithSSHTransport overrides the SSH transport (tests).
func (s *Service) WithSSHTransport(t SSHTransport) *Service {
	s.transport = t
	return s
}

// WithCredentialService wires the credential resolver.
func (s *Service) WithCredentialService(c *credential.Service) *Service {
	s.credSvc = c
	return s
}

// WithHostLookup wires the host-row reader.
func (s *Service) WithHostLookup(h HostLookup) *Service {
	s.lookup = h
	return s
}

// hostFacts is the internal hand-off used by runCycleWithTransport so
// tests can build it directly. cred can be nil when the stub transport
// ignores credentials.
type hostFacts struct {
	HostID uuid.UUID
	Addr   string
	Port   int
	Cred   *credential.Credential
}

// PoolHostLookup is the production HostLookup. Reads addr + port from
// the hosts table.
type PoolHostLookup struct {
	Pool *pgxpool.Pool
}

// GetForIntelligence returns the host's address + port. ErrHostNotFound
// when the host is missing or soft-deleted.
func (p PoolHostLookup) GetForIntelligence(ctx context.Context, hostID uuid.UUID) (Addr, error) {
	const q = `
		SELECT host(ip_address), COALESCE(port, 22)
		  FROM hosts
		 WHERE id = $1 AND deleted_at IS NULL`
	var addr Addr
	if err := p.Pool.QueryRow(ctx, q, hostID).Scan(&addr.Host, &addr.Port); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Addr{}, ErrHostNotFound
		}
		return Addr{}, fmt.Errorf("collector: lookup host: %w", err)
	}
	return addr, nil
}

// ErrHostNotFound is returned when the host id is unknown or
// soft-deleted.
var ErrHostNotFound = errors.New("collector: host not found")

// RunCycle runs one Intelligence cycle for hostID. Resolves credential,
// opens ONE SSH session, runs the probe batch, parses, diffs against
// the prior snapshot, appends event rows, UPSERTs the new snapshot,
// publishes per-change bus events, and emits per-code audit events.
//
// Returns the diff list on success. Failure to load the prior snapshot
// is treated as "first ever run" — current vs empty Snapshot gives a
// full "everything is new" diff which is suppressed by AC-13 logic
// (services/users that didn't exist before don't emit).
func (s *Service) RunCycle(ctx context.Context, hostID uuid.UUID) ([]Event, error) {
	if s.lookup == nil {
		return nil, errors.New("collector: host lookup not wired")
	}
	if s.credSvc == nil {
		return nil, errors.New("collector: credential service not wired")
	}
	addr, err := s.lookup.GetForIntelligence(ctx, hostID)
	if err != nil {
		return nil, err
	}
	cred, err := s.credSvc.Resolve(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("collector: resolve credential: %w", err)
	}
	hf := hostFacts{
		HostID: hostID,
		Addr:   addr.Host,
		Port:   addr.Port,
		Cred:   cred,
	}

	snapshot, err := s.runCycleWithTransport(ctx, hf)
	if err != nil {
		return nil, err
	}

	prior, err := s.loadPriorSnapshot(ctx, hostID)
	if err != nil {
		return nil, err
	}

	events := Diff(prior, snapshot)
	if err := s.persist(ctx, hostID, snapshot, events); err != nil {
		return nil, err
	}
	corrID, _ := correlation.From(ctx)
	for _, ev := range events {
		s.publishEvent(ctx, hostID, ev)
		s.emitAuditFor(ctx, hostID, ev, corrID)
	}
	return events, nil
}

// runCycleWithTransport opens one SSH session and runs the probe batch.
// Pure: no DB, no audit, no bus. The transport seam lets tests assert
// AC-09 (one dial per call) and AC-10 (partial success on sudo failure).
func (s *Service) runCycleWithTransport(ctx context.Context, hf hostFacts) (Snapshot, error) {
	if s.transport == nil {
		return Snapshot{}, errors.New("collector: ssh transport not wired")
	}
	sess, err := s.transport.Dial(ctx, hf.Addr, hf.Port, hf.Cred)
	if err != nil {
		return Snapshot{}, fmt.Errorf("collector: dial: %w", err)
	}
	defer sess.Close()

	snap := Snapshot{CollectedAt: time.Now().UTC()}

	if out, code, err := sess.Run(ctx, "cat /etc/passwd"); err == nil && code == 0 {
		if shadow, scode, serr := sess.Run(ctx, "sudo -n cat /etc/shadow"); serr == nil && scode == 0 {
			af, _ := ParsePasswdShadow(out, shadow)
			snap.Users = af.Users
		} else {
			af, _ := ParsePasswdShadow(out, nil)
			snap.Users = af.Users
		}
	}

	if out, code, err := sess.Run(ctx, "getent group"); err == nil && code == 0 {
		snap.Groups = parseGroupOutput(out)
	}

	if out, code, err := sess.Run(ctx, "ss -tln"); err == nil && code == 0 {
		ports, _ := ParseListeningPorts(out)
		snap.ListeningPorts = ports
	}

	if out, code, err := sess.Run(ctx, "rpm -qa --queryformat='%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null || dpkg -l 2>/dev/null"); err == nil && code == 0 {
		pkgs, _ := ParseInstalledPackages(out)
		snap.Packages = pkgs
	}

	if out, code, err := sess.Run(ctx, "systemctl list-units --type=service --all --no-legend --plain"); err == nil && code == 0 {
		snap.Services = parseSystemctlUnits(out)
	}

	if out, code, err := sess.Run(ctx, "uname -r"); err == nil && code == 0 {
		snap.KernelRelease = strings.TrimSpace(string(out))
	}

	// Reboot marker — present on Debian-family; some RHEL setups expose
	// it differently but the marker file is the canonical signal.
	if _, code, _ := sess.Run(ctx, "test -f /var/run/reboot-required || test -f /run/reboot-required"); code == 0 {
		snap.RebootRequired = true
	}

	if out, code, err := sess.Run(ctx, "cat /proc/uptime"); err == nil && code == 0 {
		snap.UptimeSeconds = parseUptime(out)
	}

	if out, code, err := sess.Run(ctx, "cat /proc/mounts"); err == nil && code == 0 {
		snap.Mountpoints = parseProcMounts(out)
	}

	// Config hashes — small fixed set. sha256 keeps the JSONB short.
	snap.ConfigHashes = map[string]string{}
	for _, path := range []string{"/etc/sudoers", "/etc/ssh/sshd_config", "/etc/passwd", "/etc/shadow"} {
		// sha256sum needs read perms; /etc/shadow needs sudo. Failures
		// (sudo denied) silently drop the entry — partial success.
		var cmd string
		if path == "/etc/shadow" {
			cmd = "sudo -n sha256sum " + path
		} else {
			cmd = "sha256sum " + path
		}
		if out, code, err := sess.Run(ctx, cmd); err == nil && code == 0 {
			h := strings.Fields(string(out))
			if len(h) >= 1 {
				snap.ConfigHashes[path] = h[0]
			}
		}
	}

	return snap, nil
}

// loadPriorSnapshot reads the prior cycle's snapshot from
// host_intelligence_state. Missing row → empty Snapshot.
func (s *Service) loadPriorSnapshot(ctx context.Context, hostID uuid.UUID) (Snapshot, error) {
	if s.pool == nil {
		return Snapshot{}, nil
	}
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT snapshot FROM host_intelligence_state WHERE host_id = $1`,
		hostID,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Snapshot{}, nil
		}
		return Snapshot{}, fmt.Errorf("collector: load prior: %w", err)
	}
	var snap Snapshot
	if uerr := json.Unmarshal(raw, &snap); uerr != nil {
		return Snapshot{}, fmt.Errorf("collector: decode prior: %w", uerr)
	}
	return snap, nil
}

// persist UPSERTs host_intelligence_state AND appends event rows in
// ONE transaction. Spec C-03 + C-04.
func (s *Service) persist(ctx context.Context, hostID uuid.UUID, snap Snapshot, events []Event) error {
	if s.pool == nil {
		return errors.New("collector: db pool not wired")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("collector: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	raw, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("collector: encode snapshot: %w", err)
	}
	// Spec C-03: UPSERT keyed by host_id.
	if _, err := tx.Exec(ctx, `
		INSERT INTO host_intelligence_state (host_id, snapshot, collected_at, created_at, updated_at)
		VALUES ($1, $2, $3, now(), now())
		ON CONFLICT (host_id) DO UPDATE SET
			snapshot     = EXCLUDED.snapshot,
			collected_at = EXCLUDED.collected_at,
			updated_at   = now()`,
		hostID, raw, snap.CollectedAt,
	); err != nil {
		return fmt.Errorf("collector: upsert state: %w", err)
	}

	// Spec C-04 + AC-14: append event rows, ignoring duplicates per
	// UNIQUE (host_id, event_code, occurred_at). ON CONFLICT DO NOTHING
	// keeps the cycle idempotent.
	corrID, _ := correlation.From(ctx)
	for _, ev := range events {
		// Hash the detail to produce a stable occurred_at-equivalent
		// timestamp; we don't have host-side timestamps for the change
		// so we use the snapshot collected_at as the canonical
		// occurred_at and let the UNIQUE constraint dedupe.
		detail, _ := json.Marshal(ev.Detail)
		_, err := tx.Exec(ctx, `
			INSERT INTO host_intelligence_events
				(id, host_id, event_code, severity, detail, occurred_at, detected_at, correlation_id)
			VALUES ($1, $2, $3, $4, $5, $6, now(), $7)
			ON CONFLICT (host_id, event_code, occurred_at) DO NOTHING`,
			uuid.Must(uuid.NewV7()), hostID, string(ev.Code), ev.Severity,
			detail, snap.CollectedAt, corrID,
		)
		if err != nil {
			return fmt.Errorf("collector: insert event %s: %w", ev.Code, err)
		}
	}
	return tx.Commit(ctx)
}

// publishEvent dispatches an IntelligenceEvent to the bus.
func (s *Service) publishEvent(ctx context.Context, hostID uuid.UUID, ev Event) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(ctx, eventbus.IntelligenceEvent{
		HostID:     hostID,
		Code:       string(ev.Code),
		Severity:   ev.Severity,
		Detail:     ev.Detail,
		OccurredAt: time.Now().UTC(),
	})
}

// emitAuditFor emits the audit event whose code matches the taxonomy
// entry. The audit codegen has registered each code as an audit.Code
// const; we look it up via the string-keyed Metadata map at call time
// so we don't have to hand-write a 28-case switch.
func (s *Service) emitAuditFor(ctx context.Context, hostID uuid.UUID, ev Event, corrID string) {
	if s.emit == nil {
		return
	}
	code := audit.Code(ev.Code)
	if _, ok := audit.Metadata[code]; !ok {
		return // unknown code — should be caught by AC-02, defensive only
	}
	s.emit(ctx, code, audit.Event{
		CorrelationID: corrID,
		ResourceType:  "host",
		ResourceID:    hostID.String(),
		Outcome:       audit.OutcomeSuccess,
		Detail:        audit.MakeDetail(ev.Detail),
	})
}

// ---- helpers ---------------------------------------------------------------

// parseGroupOutput parses `getent group` (group:passwd:gid:members).
func parseGroupOutput(b []byte) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		members := strings.Split(fields[3], ",")
		// Drop empty member.
		cleaned := make([]string, 0, len(members))
		for _, m := range members {
			if m = strings.TrimSpace(m); m != "" {
				cleaned = append(cleaned, m)
			}
		}
		out[name] = cleaned
	}
	return out
}

// parseSystemctlUnits parses `systemctl list-units --type=service`.
// Each line: "name.service  loaded active running description"
func parseSystemctlUnits(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		unit, active := fields[0], fields[2]
		out[unit] = active
	}
	return out
}

// parseUptime parses /proc/uptime ("uptime_seconds idle_seconds").
func parseUptime(b []byte) int64 {
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	// uptime is float; truncate to int. We don't care about the fractional second.
	parts := strings.Split(fields[0], ".")
	if len(parts) == 0 {
		return 0
	}
	var n int64
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

// parseProcMounts parses /proc/mounts (source mountpoint fstype options 0 0).
func parseProcMounts(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out[fields[1]] = fields[0]
	}
	return out
}

// hashBytes is a small helper for callers that need to compute a
// content hash on parsed snapshot fields. Currently unused at the
// service level (config hashes are computed remotely via sha256sum)
// but kept handy for the future detail-hash idempotency story.
func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var _ = hashBytes // silence unused-warning until we wire it
