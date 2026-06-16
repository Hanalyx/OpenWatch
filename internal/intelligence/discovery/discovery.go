package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/intelligence/probe"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// JobKindHostDiscovery is the queue job kind for asynchronous Discovery
// runs. POST /api/v1/hosts auto-enqueues a job of this kind so the 201
// response returns immediately. Spec C-05 / AC-13.
const JobKindHostDiscovery = "host.discovery"

// HostDiscoveryJobPayload is the JSON shape of the host.discovery job
// payload the worker reads. Carries the host id so the worker can
// invoke Service.Discover. Exported so the worker package can decode
// it without importing service internals.
type HostDiscoveryJobPayload struct {
	HostID uuid.UUID `json:"host_id"`
}

// PoolHostLookup adapts a *pgxpool.Pool into the HostLookup interface
// expected by Service. Production wires this; tests stub the
// interface directly.
type PoolHostLookup struct {
	Pool *pgxpool.Pool
}

// GetForDiscovery reads the host's address + port. Returns
// pgx.ErrNoRows-like sentinel via a separate ErrHostNotFound if the
// host is missing or soft-deleted.
func (p PoolHostLookup) GetForDiscovery(ctx context.Context, hostID uuid.UUID) (Addr, error) {
	const q = `
		SELECT host(ip_address), COALESCE(port, 22)
		  FROM hosts
		 WHERE id = $1 AND deleted_at IS NULL`
	var addr Addr
	if err := p.Pool.QueryRow(ctx, q, hostID).Scan(&addr.Host, &addr.Port); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Addr{}, ErrHostNotFound
		}
		return Addr{}, fmt.Errorf("discovery: lookup host: %w", err)
	}
	return addr, nil
}

// ErrHostNotFound is returned by HostLookup.GetForDiscovery when the
// host is unknown or soft-deleted. The handler maps this to HTTP 404.
var ErrHostNotFound = errors.New("discovery: host not found")

// RunDiscovery is the error-only adapter the worker uses (matches
// worker.HostDiscoveryRunner interface signature). Discards the
// SystemFacts return — the worker only cares about success / failure,
// since persist + bus + audit are already done inside Discover.
func (s *Service) RunDiscovery(ctx context.Context, hostID uuid.UUID) error {
	_, err := s.Discover(ctx, hostID)
	return err
}

// SystemFacts is the typed bundle of every fact one Discover run
// collected. Mirrors the host_system_info column layout one-for-one so
// persist() is a straight value-to-column map.
type SystemFacts struct {
	// /etc/os-release
	OSName             string
	OSVersion          string
	OSVersionFull      string
	OSID               string
	OSIDLike           string
	OSPrettyName       string
	PlatformIdentifier string
	OSFamily           string // derived from OSID + OSIDLike

	// uname -srvm
	KernelName    string
	KernelRelease string
	KernelVersion string
	Architecture  string

	// /proc/meminfo (MB)
	MemTotalMB     int
	MemAvailableMB int
	SwapTotalMB    int

	// df -BG /
	DiskTotalGB int
	DiskUsedGB  int
	DiskFreeGB  int

	// hostname
	Hostname string
	FQDN     string

	// security posture
	SELinuxStatus   string
	AppArmorEnabled bool

	// firewall (may be empty when sudo unavailable)
	FirewallService string
	FirewallStatus  string

	CollectedAt time.Time
}

// AuditEmitFunc is the audit emission seam. Production wires it to
// audit.Emit; tests use a recorder that counts emissions.
type AuditEmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// Publisher is the event-bus subset Discovery uses. The real
// *eventbus.Bus satisfies it; tests inject a recorder.
type Publisher interface {
	Publish(ctx context.Context, event eventbus.Event)
}

// HostLookup is the seam Discovery uses to read host connection facts
// (addr, port) without coupling to the hosts package's full repository
// API. Production: a small adapter over pgxpool. Tests pre-build the
// hostFacts and use discoverWithTransport directly.
type HostLookup interface {
	GetForDiscovery(ctx context.Context, hostID uuid.UUID) (Addr, error)
}

// Addr holds the minimal host-connection tuple Discovery needs.
type Addr struct {
	Host string
	Port int
}

// Service runs Discovery for a host. Construct via NewService.
// PolicyLoader returns the current SecurityConfig — the sudo-password
// fallback (system-ssh-connectivity v1.2.0 C-09 / AC-20) consults
// AllowCredentialSudoPassword via this seam. Production wires
// systemconfig.Store.LoadSecurity; tests pass a closure or leave it
// nil (in which case the fallback path is OFF by default).
type PolicyLoader interface {
	LoadSecurity(ctx context.Context) (systemconfig.SecurityConfig, error)
}

type Service struct {
	pool      *pgxpool.Pool
	credSvc   *credential.Service
	emit      AuditEmitFunc
	bus       Publisher
	lookup    HostLookup
	transport SSHTransport
	policy    PolicyLoader
}

// NewService constructs a Service. emit + bus may be nil — Discover
// degrades gracefully (audit + publish skip). credSvc may be nil for
// tests that only exercise the discoverWithTransport seam.
//
// A production SSH transport (TOFU host-key policy, in-memory known-
// hosts store) is installed by default. Tests override via
// WithSSHTransport; cmd/openwatch can swap in a strict / persistent
// store via NewSSHTransport + WithSSHTransport before Run.
func NewService(pool *pgxpool.Pool, emit AuditEmitFunc, bus Publisher) *Service {
	return &Service{
		pool:      pool,
		emit:      emit,
		bus:       bus,
		transport: NewSSHTransport(owssh.ModeTOFU, owssh.NewMemoryStore()),
	}
}

// WithSSHTransport overrides the SSH transport (tests).
func (s *Service) WithSSHTransport(t SSHTransport) *Service {
	s.transport = t
	return s
}

// WithCredentialService wires the credential resolver. Required for
// Discover; not required for discoverWithTransport.
func (s *Service) WithCredentialService(c *credential.Service) *Service {
	s.credSvc = c
	return s
}

// WithHostLookup wires the host-row reader. Required for Discover.
func (s *Service) WithHostLookup(h HostLookup) *Service {
	s.lookup = h
	return s
}

// WithPolicyLoader wires the SecurityConfig reader. When unset, the
// sudo-password fallback (v1.2.0 AC-20) stays OFF — probeFirewall
// behaves exactly as in v1.1.0.
func (s *Service) WithPolicyLoader(p PolicyLoader) *Service {
	s.policy = p
	return s
}

// hostFacts is the internal hand-off from Discover (which knows the
// hostID and pulls addr + cred) to discoverWithTransport (which only
// needs the prepared tuple). Tests build it directly.
type hostFacts struct {
	HostID uuid.UUID
	Addr   string
	Port   int
	Cred   *credential.Credential
}

// Discover runs one full Discovery for hostID. Resolves credential,
// opens ONE SSH session, runs the probe batch, parses, persists in a
// single transaction, publishes the bus event, emits the audit event.
//
// Returns SystemFacts on success (including the partial-success path
// where sudo was unavailable for firewall introspection — facts.Firewall*
// stays empty in that case). Errors come from credential resolution,
// SSH dial, or persistence — never from a sub-command's non-zero exit.
func (s *Service) Discover(ctx context.Context, hostID uuid.UUID) (SystemFacts, error) {
	if s.lookup == nil {
		return SystemFacts{}, errors.New("discovery: host lookup not wired")
	}
	if s.credSvc == nil {
		return SystemFacts{}, errors.New("discovery: credential service not wired")
	}

	addr, err := s.lookup.GetForDiscovery(ctx, hostID)
	if err != nil {
		return SystemFacts{}, fmt.Errorf("discovery: host lookup: %w", err)
	}

	cred, err := s.credSvc.Resolve(ctx, hostID)
	if err != nil {
		return SystemFacts{}, fmt.Errorf("discovery: resolve credential: %w", err)
	}

	hf := hostFacts{
		HostID: hostID,
		Addr:   addr.Host,
		Port:   addr.Port,
		Cred:   cred,
	}
	facts, err := s.discoverWithTransport(ctx, hf)
	if err != nil {
		return SystemFacts{}, err
	}

	if err := s.persist(ctx, hostID, facts); err != nil {
		return SystemFacts{}, fmt.Errorf("discovery: persist: %w", err)
	}
	s.publishBusEvent(hostID, facts)
	s.emitAuditSuccess(ctx, hostID, facts)
	return facts, nil
}

// discoverWithTransport is the inner loop that opens one SSH session
// and runs the closed probe batch. Pure: no DB, no audit, no bus. The
// transport seam lets tests assert AC-06 (one dial per call) and AC-05
// (partial success on sudo failure) without any network I/O.
func (s *Service) discoverWithTransport(ctx context.Context, hf hostFacts) (SystemFacts, error) {
	if s.transport == nil {
		return SystemFacts{}, errors.New("discovery: ssh transport not wired")
	}

	// Carry the host id so a profile-aware transport can lead with this
	// host's known-good SSH auth method and record what authenticated.
	ctx = connprofile.WithHostID(ctx, hf.HostID)

	sess, err := s.transport.Dial(ctx, hf.Addr, hf.Port, hf.Cred)
	if err != nil {
		return SystemFacts{}, fmt.Errorf("discovery: dial: %w", err)
	}
	defer sess.Close()

	facts := SystemFacts{CollectedAt: time.Now().UTC()}

	// World-readable probes — sudo not required.
	if out, code, err := sess.Run(ctx, "cat /etc/os-release"); err == nil && code == 0 {
		osf, _ := probe.ParseOSRelease(out)
		facts.OSName = osf.OSName
		facts.OSVersion = osf.OSVersion
		facts.OSVersionFull = osf.OSVersionFull
		facts.OSID = osf.OSID
		facts.OSIDLike = osf.OSIDLike
		facts.OSPrettyName = osf.OSPrettyName
		facts.PlatformIdentifier = osf.PlatformIdentifier
		facts.OSFamily = deriveOSFamily(osf.OSID, osf.OSIDLike)
	}

	if out, code, err := sess.Run(ctx, "uname -srvm"); err == nil && code == 0 {
		uf, _ := probe.ParseUname(out)
		facts.KernelName = uf.KernelName
		facts.KernelRelease = uf.KernelRelease
		facts.KernelVersion = uf.KernelVersion
		facts.Architecture = uf.Architecture
	}

	if out, code, err := sess.Run(ctx, "cat /proc/meminfo"); err == nil && code == 0 {
		mi, _ := probe.ParseMemInfo(out)
		facts.MemTotalMB = mi.MemTotalMB
		facts.MemAvailableMB = mi.MemAvailableMB
		facts.SwapTotalMB = mi.SwapTotalMB
	}

	if out, code, err := sess.Run(ctx, "df -BG /"); err == nil && code == 0 {
		total, used, free := parseDfRoot(out)
		facts.DiskTotalGB = total
		facts.DiskUsedGB = used
		facts.DiskFreeGB = free
	}

	if out, code, err := sess.Run(ctx, "hostname"); err == nil && code == 0 {
		facts.Hostname = strings.TrimSpace(string(out))
	}
	if out, code, err := sess.Run(ctx, "hostname -f"); err == nil && code == 0 {
		facts.FQDN = strings.TrimSpace(string(out))
	}

	if out, code, err := sess.Run(ctx, "getenforce"); err == nil && code == 0 {
		facts.SELinuxStatus = strings.TrimSpace(string(out))
	}
	if _, code, err := sess.Run(ctx, "aa-status --enabled"); err == nil {
		// aa-status --enabled exits 0 when enabled, 1 when not.
		facts.AppArmorEnabled = code == 0
	}

	// Firewall introspection — needs sudo on most distros. Per spec C-03
	// + AC-05, sudo failure is partial success: leave fields empty and
	// continue. v1.2.0 — when AllowCredentialSudoPassword is set,
	// runSudoWithFallback retries a sudo -n failure as sudo -S -k -p ''
	// with the credential password before the probe falls through.
	cfg := sudoFallbackConfig{cred: hf.Cred}
	if s.policy != nil {
		if sec, lerr := s.policy.LoadSecurity(ctx); lerr == nil {
			cfg.policy = sec
		}
	}
	if svc, status, ok := probeFirewall(ctx, sess, cfg); ok {
		facts.FirewallService = svc
		facts.FirewallStatus = status
	}

	return facts, nil
}

// persist UPSERTs host_system_info AND updates the denormalized
// hosts.os_* columns in ONE transaction (spec C-02 + AC-07). The
// host_system_info UPSERT uses ON CONFLICT (host_id) DO UPDATE so a
// second Discover updates in place (spec C-08 + AC-14).
func (s *Service) persist(ctx context.Context, hostID uuid.UUID, f SystemFacts) error {
	if s.pool == nil {
		return errors.New("discovery: db pool not wired")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("discovery: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const upsertSystemInfo = `
		INSERT INTO host_system_info (
			host_id,
			os_name, os_version, os_version_full, os_id, os_id_like,
			os_pretty_name, platform_identifier, os_family,
			kernel_name, kernel_release, kernel_version, architecture,
			mem_total_mb, mem_available_mb, swap_total_mb,
			disk_total_gb, disk_used_gb, disk_free_gb,
			hostname, fqdn,
			selinux_status, apparmor_enabled,
			firewall_service, firewall_status,
			collected_at, created_at, updated_at
		) VALUES (
			$1,
			$2, $3, $4, $5, $6,
			$7, $8, $9,
			$10, $11, $12, $13,
			$14, $15, $16,
			$17, $18, $19,
			$20, $21,
			$22, $23,
			$24, $25,
			$26, now(), now()
		)
		ON CONFLICT (host_id) DO UPDATE SET
			os_name             = EXCLUDED.os_name,
			os_version          = EXCLUDED.os_version,
			os_version_full     = EXCLUDED.os_version_full,
			os_id               = EXCLUDED.os_id,
			os_id_like          = EXCLUDED.os_id_like,
			os_pretty_name      = EXCLUDED.os_pretty_name,
			platform_identifier = EXCLUDED.platform_identifier,
			os_family           = EXCLUDED.os_family,
			kernel_name         = EXCLUDED.kernel_name,
			kernel_release      = EXCLUDED.kernel_release,
			kernel_version      = EXCLUDED.kernel_version,
			architecture        = EXCLUDED.architecture,
			mem_total_mb        = EXCLUDED.mem_total_mb,
			mem_available_mb    = EXCLUDED.mem_available_mb,
			swap_total_mb       = EXCLUDED.swap_total_mb,
			disk_total_gb       = EXCLUDED.disk_total_gb,
			disk_used_gb        = EXCLUDED.disk_used_gb,
			disk_free_gb        = EXCLUDED.disk_free_gb,
			hostname            = EXCLUDED.hostname,
			fqdn                = EXCLUDED.fqdn,
			selinux_status      = EXCLUDED.selinux_status,
			apparmor_enabled    = EXCLUDED.apparmor_enabled,
			firewall_service    = EXCLUDED.firewall_service,
			firewall_status     = EXCLUDED.firewall_status,
			collected_at        = EXCLUDED.collected_at,
			updated_at          = now()`

	if _, err := tx.Exec(ctx, upsertSystemInfo,
		hostID,
		nilIfEmpty(f.OSName), nilIfEmpty(f.OSVersion), nilIfEmpty(f.OSVersionFull),
		nilIfEmpty(f.OSID), nilIfEmpty(f.OSIDLike),
		nilIfEmpty(f.OSPrettyName), nilIfEmpty(f.PlatformIdentifier), nilIfEmpty(f.OSFamily),
		nilIfEmpty(f.KernelName), nilIfEmpty(f.KernelRelease), nilIfEmpty(f.KernelVersion), nilIfEmpty(f.Architecture),
		nilIfZero(f.MemTotalMB), nilIfZero(f.MemAvailableMB), nilIfZero(f.SwapTotalMB),
		nilIfZero(f.DiskTotalGB), nilIfZero(f.DiskUsedGB), nilIfZero(f.DiskFreeGB),
		nilIfEmpty(f.Hostname), nilIfEmpty(f.FQDN),
		nilIfEmpty(f.SELinuxStatus), f.AppArmorEnabled,
		nilIfEmpty(f.FirewallService), nilIfEmpty(f.FirewallStatus),
		f.CollectedAt,
	); err != nil {
		return fmt.Errorf("discovery: upsert host_system_info: %w", err)
	}

	// Denormalized columns on hosts — list-page filters read here.
	const updateHosts = `
		UPDATE hosts SET
			os_family           = $2,
			os_version          = $3,
			architecture        = $4,
			platform_identifier = $5,
			os_discovered_at    = now(),
			updated_at          = now()
		WHERE id = $1 AND deleted_at IS NULL`
	if _, err := tx.Exec(ctx, updateHosts,
		hostID,
		nilIfEmpty(f.OSFamily),
		nilIfEmpty(f.OSVersion),
		nilIfEmpty(f.Architecture),
		nilIfEmpty(f.PlatformIdentifier),
	); err != nil {
		return fmt.Errorf("discovery: update hosts os_family: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("discovery: commit: %w", err)
	}
	return nil
}

// publishBusEvent emits HostDiscovered on the eventbus. Best-effort —
// bus errors are not surfaced (matches HeartbeatPulse semantics).
func (s *Service) publishBusEvent(hostID uuid.UUID, f SystemFacts) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(context.Background(), eventbus.HostDiscovered{
		HostID:       hostID,
		OSFamily:     f.OSFamily,
		OSVersion:    f.OSVersion,
		DiscoveredAt: f.CollectedAt,
	})
}

// emitAuditSuccess records host.discovery.completed for the success
// path. Per spec C-07, failure paths must NOT emit.
func (s *Service) emitAuditSuccess(ctx context.Context, hostID uuid.UUID, f SystemFacts) {
	if s.emit == nil {
		return
	}
	s.emit(ctx, audit.HostDiscoveryCompleted, audit.Event{
		ResourceType: "host",
		ResourceID:   hostID.String(),
		Outcome:      audit.OutcomeSuccess,
		Detail: audit.MakeDetail(map[string]any{
			"os_family":      f.OSFamily,
			"os_version":     f.OSVersion,
			"kernel_release": f.KernelRelease,
			"architecture":   f.Architecture,
			"discovered_at":  f.CollectedAt.Format(time.RFC3339Nano),
		}),
	})
}
