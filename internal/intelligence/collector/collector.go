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
	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
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
//
// RunWithStdin is the sudo-password-fallback hook (system-ssh-connectivity
// v1.1.0 C-10). When the credential carries a password and the system
// policy allows it, ssh.RunSudo feeds the password via this method's
// stdin parameter — never via cmd. Implementations that don't support
// stdin can return (nil, 0, errors.New("not supported")) but then will
// not handle hosts that lack NOPASSWD.
type SSHSession interface {
	Run(ctx context.Context, cmd string) (stdout []byte, exitCode int, err error)
	RunWithStdin(ctx context.Context, cmd string, stdin []byte) (stdout []byte, exitCode int, err error)
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

// SudoPolicyLoader returns the current sudo policy at cycle start. The
// production wiring reads system_config.security.allow_credential_sudo_password
// via systemconfig.Store.LoadSecurity. Tests substitute a constant.
type SudoPolicyLoader func(ctx context.Context) (owssh.SudoPolicy, error)

// ConnProfileStore is the subset of connprofile the collector uses to
// learn the host's SUDO mode: lead each cycle's sudo commands with the
// recorded mode and record the mode that actually worked. nil disables
// sudo-mode learning. (SSH auth-method learning is handled separately by
// the profile-aware transport.) Spec system-connection-profile v1.2.0.
type ConnProfileStore interface {
	Get(ctx context.Context, hostID uuid.UUID) (connprofile.Profile, error)
	RecordSudoMode(ctx context.Context, hostID uuid.UUID, m connprofile.SudoMode) error
}

// Service is the OS Intelligence collector. Construct via NewService.
type Service struct {
	pool       *pgxpool.Pool
	credSvc    *credential.Service
	emit       AuditEmitFunc
	bus        Publisher
	lookup     HostLookup
	transport  SSHTransport
	sudoPolicy SudoPolicyLoader
	profiles   ConnProfileStore
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

// WithSudoPolicyLoader wires the policy loader. When unset, the
// collector falls back to a permanently-disabled policy — every cycle
// runs `sudo -n only`, identical to v1.0.0 behavior. Spec: system-
// ssh-connectivity v1.1.0 C-09.
func (s *Service) WithSudoPolicyLoader(l SudoPolicyLoader) *Service {
	s.sudoPolicy = l
	return s
}

// WithProfiles enables per-host sudo-mode learning: each cycle leads its
// sudo commands with the host's recorded mode and records the mode that
// worked. nil (the default) keeps the historical sudo -n-first probing.
// Spec system-connection-profile v1.2.0 C-07 / AC-10.
func (s *Service) WithProfiles(p ConnProfileStore) *Service {
	s.profiles = p
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

	snapshot, sudoFallbackCount, err := s.runCycleWithTransport(ctx, hf)
	if err != nil {
		return nil, err
	}

	prior, err := s.loadPriorSnapshot(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// No-clobber (spec C-03, v1.2.0): carry forward the prior value for any
	// category this cycle did NOT observe, BEFORE diffing and persisting, so a
	// failed or denied probe neither emits a false change event nor blanks the
	// stored snapshot.
	snapshot = mergeUnobserved(snapshot, prior)

	events := Diff(prior, snapshot)
	if err := s.persist(ctx, hostID, snapshot, events); err != nil {
		return nil, err
	}
	corrID, _ := correlation.From(ctx)
	for _, ev := range events {
		s.publishEvent(ctx, hostID, ev)
		s.emitAuditFor(ctx, hostID, ev, corrID)
	}
	// Spec system-ssh-connectivity v1.1.0 AC-16: exactly one audit
	// event per host per cycle when the credential-password fallback
	// engaged for at least one sudo command. detail.credential_id
	// identifies the secret used; detail.command_count is the number
	// of distinct sudo calls that hit the fallback.
	if sudoFallbackCount > 0 && s.emit != nil {
		detail, _ := json.Marshal(map[string]any{
			"credential_id": cred.ID.String(),
			"host_id":       hostID.String(),
			"command_count": sudoFallbackCount,
		})
		s.emit(ctx, audit.SystemIntelligenceSudoPasswordUsed, audit.Event{
			ActorType: "system",
			ActorID:   "intelligence-collector",
			Detail:    detail,
		})
	}
	return events, nil
}

// runCycleWithTransport opens one SSH session and runs the probe batch.
// Pure: no DB, no audit, no bus. The transport seam lets tests assert
// AC-09 (one dial per call) and AC-10 (partial success on sudo failure).
//
// Returns the snapshot AND a count of distinct sudo invocations that
// used the credential-password fallback (system-ssh-connectivity
// v1.1.0 C-09 / AC-16). The caller (RunCycle) translates a non-zero
// count into one audit event per host per cycle.
func (s *Service) runCycleWithTransport(ctx context.Context, hf hostFacts) (Snapshot, int, error) {
	if s.transport == nil {
		return Snapshot{}, 0, errors.New("collector: ssh transport not wired")
	}
	// Carry the host id so a profile-aware transport can lead with this
	// host's known-good SSH auth method and record what authenticated.
	ctx = connprofile.WithHostID(ctx, hf.HostID)
	sess, err := s.transport.Dial(ctx, hf.Addr, hf.Port, hf.Cred)
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("collector: dial: %w", err)
	}
	defer sess.Close()

	// Load the sudo policy once per cycle. Loader failures degrade
	// to "policy off" rather than crashing the cycle — partial-
	// success is the prevailing failure mode in this layer.
	var policy owssh.SudoPolicy
	if s.sudoPolicy != nil {
		if p, perr := s.sudoPolicy(ctx); perr == nil {
			policy = p
		}
	}
	sudoFallbackCount := 0

	// Sudo-mode learning: lead this cycle's sudo commands with the host's
	// recorded mode (skips the doomed `sudo -n` on a password-sudo host),
	// observe what actually worked, and record it once at cycle end.
	// sudoPrefer threads the observation forward so later sudo commands in
	// the same cycle also lead correctly. Spec system-connection-profile
	// v1.2.0 C-07.
	var knownSudo, learnedSudo connprofile.SudoMode
	if s.profiles != nil {
		if p, perr := s.profiles.Get(ctx, hf.HostID); perr == nil {
			knownSudo = p.SudoMode
		}
	}
	sudoPrefer := string(knownSudo)
	observeSudo := func(observed string) {
		if observed != "" {
			learnedSudo = connprofile.SudoMode(observed)
			sudoPrefer = observed
		}
	}

	snap := Snapshot{CollectedAt: time.Now().UTC(), Observed: map[SnapCategory]bool{}}

	if out, code, err := sess.Run(ctx, "cat /etc/passwd"); err == nil && code == 0 {
		snap.Observed[SnapUsers] = true
		// Spec v1.1.0 C-09: sudo -n first; sudo -S -k with cred.Password
		// on fallback if policy + credential allow.
		shadow, scode, used, observed, serr := owssh.RunSudo(ctx, sess, hf.Cred, policy, sudoPrefer, "cat /etc/shadow")
		observeSudo(observed)
		if used {
			sudoFallbackCount++
		}
		if serr == nil && scode == 0 {
			af, _ := ParsePasswdShadow(out, shadow)
			snap.Users = af.Users
		} else {
			af, _ := ParsePasswdShadow(out, nil)
			snap.Users = af.Users
		}
	} else {
		snap.recordFailure(SnapUsers, out, err)
	}

	if out, code, err := sess.Run(ctx, "getent group"); err == nil && code == 0 {
		snap.Groups = parseGroupOutput(out)
		snap.Observed[SnapGroups] = true
	} else {
		snap.recordFailure(SnapGroups, out, err)
	}

	if out, code, err := sess.Run(ctx, "ss -tln"); err == nil && code == 0 {
		ports, _ := ParseListeningPorts(out)
		snap.ListeningPorts = ports
		snap.Observed[SnapPorts] = true
	} else {
		snap.recordFailure(SnapPorts, out, err)
	}

	// Network interfaces: `ip -j addr` gives addresses + state + MAC +
	// MTU; the sysfs probe fills in driver/speed/duplex/RX/TX. Partial
	// success — if the sysfs loop fails we still surface the IP info.
	if out, code, err := sess.Run(ctx, "ip -j addr show 2>/dev/null"); err == nil && code == 0 {
		if ifaces, perr := ParseIPAddrJSON(out); perr == nil {
			stats := map[string]sysfsStats{}
			// One shell pass over /sys/class/net/. printf instead of echo for
			// portability; |-delimited so a single parser handles all hosts.
			const sysfsCmd = `for i in /sys/class/net/*; do
                name=$(basename "$i")
                speed=$(cat "$i/speed" 2>/dev/null)
                duplex=$(cat "$i/duplex" 2>/dev/null)
                drv=$(basename "$(readlink "$i/device/driver" 2>/dev/null)" 2>/dev/null)
                rx=$(cat "$i/statistics/rx_bytes" 2>/dev/null)
                tx=$(cat "$i/statistics/tx_bytes" 2>/dev/null)
                printf "%s|%s|%s|%s|%s|%s\n" "$name" "$speed" "$duplex" "$drv" "$rx" "$tx"
            done`
			if sout, scode, serr := sess.Run(ctx, sysfsCmd); serr == nil && scode == 0 {
				stats = ParseSysfsNetStats(sout)
			}
			snap.NetworkInterfaces = MergeNetworkInterfaces(ifaces, stats)
			snap.Observed[SnapInterfaces] = true
		}
	} else {
		snap.recordFailure(SnapInterfaces, out, err)
	}

	if out, code, err := sess.Run(ctx, "ip -j route show 2>/dev/null"); err == nil && code == 0 {
		if routes, perr := ParseIPRouteJSON(out); perr == nil {
			snap.Routes = routes
			snap.Observed[SnapRoutes] = true
		}
	} else {
		snap.recordFailure(SnapRoutes, out, err)
	}

	// Firewall rule count: try engines in priority order. First non-
	// empty answer wins. -1 left in place when nothing detects (so the
	// frontend can distinguish "no engine" from "0 rules"). Pointer so
	// 0 ("engine present, no rules") survives JSON omitempty.
	negOne := -1
	snap.FirewallRuleCount = &negOne
	// Non-interactive SSH PATH is minimal on Debian/Ubuntu — /usr/sbin
	// is often missing, which hides ufw + nft + iptables-save. Prepend
	// the admin paths so command -v finds them.
	// `grep -c` exits 1 when count is 0, which masks legitimate
	// "engine present, 0 rules" answers. Each branch wraps the grep
	// in `|| true` so the script's exit code stays 0 regardless of
	// rule count. Without this, sess.Run's code != 0 gate dropped
	// every ufw-inactive Ubuntu host to FirewallRuleCount=-1.
	const fwRuleCmd = `
        export PATH="$PATH:/sbin:/usr/sbin:/usr/local/sbin"
        if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
            firewall-cmd --get-active-zones 2>/dev/null \
                | grep -v "^  " \
                | while read z; do firewall-cmd --zone="$z" --list-rich-rules 2>/dev/null; done \
                | { grep -c "rule " || true; }
        elif command -v ufw >/dev/null 2>&1; then
            (sudo -n ufw status numbered 2>/dev/null || ufw status numbered 2>/dev/null) \
                | { grep -cE "^\[" || true; }
        elif command -v nft >/dev/null 2>&1; then
            (sudo -n nft list ruleset 2>/dev/null || nft list ruleset 2>/dev/null) \
                | { grep -cE "^[[:space:]]+(tcp|udp|icmp|ip6?|meta).*(drop|accept|reject)" || true; }
        elif command -v iptables-save >/dev/null 2>&1; then
            (sudo -n iptables-save 2>/dev/null || iptables-save 2>/dev/null) \
                | { grep -c "^-A" || true; }
        else
            echo ""
        fi
    `
	if out, code, err := sess.Run(ctx, fwRuleCmd); err == nil && code == 0 {
		// The probe ran: this is an observation (the value is a real count, or
		// -1 for "no engine"). Only a probe that could not run carries forward.
		snap.Observed[SnapFirewall] = true
		if n, ok := parseFirewallRuleCount(out); ok {
			nn := n
			snap.FirewallRuleCount = &nn
		}
	} else {
		snap.recordFailure(SnapFirewall, out, err)
	}

	if out, code, err := sess.Run(ctx, "rpm -qa --queryformat='%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null || dpkg -l 2>/dev/null"); err == nil && code == 0 {
		pkgs, _ := ParseInstalledPackages(out)
		snap.Packages = pkgs
		snap.Observed[SnapPackages] = true
	} else {
		snap.recordFailure(SnapPackages, out, err)
	}

	if out, code, err := sess.Run(ctx, "systemctl list-units --type=service --all --no-legend --plain"); err == nil && code == 0 {
		snap.Services = parseSystemctlUnits(out)
		snap.Observed[SnapServices] = true
	} else {
		snap.recordFailure(SnapServices, out, err)
	}

	if out, code, err := sess.Run(ctx, "uname -r"); err == nil && code == 0 {
		snap.KernelRelease = strings.TrimSpace(string(out))
		snap.Observed[SnapKernel] = true
	} else {
		snap.recordFailure(SnapKernel, out, err)
	}

	// Reboot marker — present on Debian-family; some RHEL setups expose
	// it differently but the marker file is the canonical signal.
	if _, code, _ := sess.Run(ctx, "test -f /var/run/reboot-required || test -f /run/reboot-required"); code == 0 {
		snap.RebootRequired = true
	}

	if out, code, err := sess.Run(ctx, "cat /proc/uptime"); err == nil && code == 0 {
		snap.UptimeSeconds = parseUptime(out)
		snap.Observed[SnapUptime] = true
	} else {
		snap.recordFailure(SnapUptime, out, err)
	}

	if out, code, err := sess.Run(ctx, "cat /proc/mounts"); err == nil && code == 0 {
		snap.Mountpoints = parseProcMounts(out)
		snap.Observed[SnapMounts] = true
	} else {
		snap.recordFailure(SnapMounts, out, err)
	}

	// Config hashes — small fixed set. sha256 keeps the JSONB short.
	snap.ConfigHashes = map[string]string{}
	for _, path := range []string{"/etc/sudoers", "/etc/ssh/sshd_config", "/etc/passwd", "/etc/shadow"} {
		// sha256sum needs read perms; /etc/shadow needs sudo. Failures
		// (sudo denied) silently drop the entry — partial success.
		if path == "/etc/shadow" {
			// Spec v1.1.0 C-09 — same gating as the shadow read above.
			out, code, used, observed, err := owssh.RunSudo(ctx, sess, hf.Cred, policy, sudoPrefer, "sha256sum "+path)
			observeSudo(observed)
			if used {
				sudoFallbackCount++
			}
			if err == nil && code == 0 {
				if h := strings.Fields(string(out)); len(h) >= 1 {
					snap.ConfigHashes[path] = h[0]
				}
			}
			continue
		}
		if out, code, err := sess.Run(ctx, "sha256sum "+path); err == nil && code == 0 {
			h := strings.Fields(string(out))
			if len(h) >= 1 {
				snap.ConfigHashes[path] = h[0]
			}
		}
	}
	// Config hashes are partial by nature (sudo-gated /etc/shadow may drop);
	// treat the category as observed only when at least one file hashed, so a
	// fully-denied run carries forward the prior hashes rather than blanking.
	// A fully-empty result means even the world-readable sha256sums failed —
	// a broad collection failure, classified "failed" (no single probe output
	// to attribute a specific sudo denial to).
	if len(snap.ConfigHashes) > 0 {
		snap.Observed[SnapConfig] = true
	} else {
		snap.recordFailure(SnapConfig, nil, nil)
	}

	// TODO(v1.2): the firewall-rule probe embeds three `sudo -n` calls
	// inside one shell heredoc. Wrapping them through ssh.RunSudo
	// requires splitting the probe into a detect-engine step (no sudo)
	// followed by a count-rules-for-engine step (one sudo call). Skipped
	// in v1.1.0 to keep the patch tight; the current behavior already
	// covers ufw-inactive Ubuntu hosts (count=0 via the non-sudo
	// fallback inside the heredoc).

	// Record the learned sudo mode once per cycle — only when a form was
	// confirmed AND it differs from what was already stored (a no-op
	// upsert otherwise). Spec system-connection-profile v1.2.0 C-07.
	if s.profiles != nil && learnedSudo != connprofile.SudoUnknown && learnedSudo != knownSudo {
		_ = s.profiles.RecordSudoMode(ctx, hf.HostID, learnedSudo)
	}

	return snap, sudoFallbackCount, nil
}

// mergeUnobserved carries forward prior values for every category the current
// cycle did not observe, so a failed or denied probe never overwrites good data
// with an empty result. An observed category keeps this cycle's value even when
// genuinely empty (a real observation). A nil Observed map treats all
// categories as unobserved — the safe default: preserve everything rather than
// blank. RebootRequired and CollectedAt always come from this cycle.
func mergeUnobserved(snap, prior Snapshot) Snapshot {
	obs := snap.Observed
	if !obs[SnapUsers] {
		snap.Users = prior.Users
	}
	if !obs[SnapGroups] {
		snap.Groups = prior.Groups
	}
	if !obs[SnapPorts] {
		snap.ListeningPorts = prior.ListeningPorts
	}
	if !obs[SnapInterfaces] {
		snap.NetworkInterfaces = prior.NetworkInterfaces
	}
	if !obs[SnapRoutes] {
		snap.Routes = prior.Routes
	}
	if !obs[SnapFirewall] {
		snap.FirewallRuleCount = prior.FirewallRuleCount
	}
	if !obs[SnapPackages] {
		snap.Packages = prior.Packages
	}
	if !obs[SnapServices] {
		snap.Services = prior.Services
	}
	if !obs[SnapKernel] {
		snap.KernelRelease = prior.KernelRelease
	}
	if !obs[SnapUptime] {
		snap.UptimeSeconds = prior.UptimeSeconds
	}
	if !obs[SnapMounts] {
		snap.Mountpoints = prior.Mountpoints
	}
	if !obs[SnapConfig] {
		snap.ConfigHashes = prior.ConfigHashes
	}
	return snap
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
	// Per-category freshness (spec v1.3.0): stamp when each category was last
	// observed vs merely attempted, so a consumer can tell fresh from
	// carried-forward data.
	var priorFreshRaw []byte
	if err := tx.QueryRow(ctx,
		`SELECT category_freshness FROM host_intelligence_state WHERE host_id = $1`, hostID,
	).Scan(&priorFreshRaw); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("collector: read prior freshness: %w", err)
	}
	var priorFresh map[string]snapFreshnessEntry
	if len(priorFreshRaw) > 0 {
		_ = json.Unmarshal(priorFreshRaw, &priorFresh)
	}
	freshJSON, _ := json.Marshal(computeSnapFreshness(snap.Observed, snap.Attempts, priorFresh, snap.CollectedAt))

	// Spec C-03: UPSERT keyed by host_id.
	if _, err := tx.Exec(ctx, `
		INSERT INTO host_intelligence_state (host_id, snapshot, collected_at, category_freshness, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now(), now())
		ON CONFLICT (host_id) DO UPDATE SET
			snapshot           = EXCLUDED.snapshot,
			collected_at       = EXCLUDED.collected_at,
			category_freshness = EXCLUDED.category_freshness,
			updated_at         = now()`,
		hostID, raw, snap.CollectedAt, freshJSON,
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
