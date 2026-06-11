package discovery

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/google/uuid"
)

// testCtx returns a context with a correlation_id and a per-test cancel.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return correlation.Set(ctx, uuid.NewString())
}

// testHostFacts returns a deterministic hostFacts for tests. Cred is
// nil because the stub transport ignores it.
func testHostFacts() hostFacts {
	return hostFacts{
		HostID: uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		Addr:   "test.local",
		Port:   22,
		Cred:   nil,
	}
}

// ---- stub SSH transport ---------------------------------------------------

type stubSSHTransport struct {
	mu         sync.Mutex
	dialCount  atomic.Int64
	outputs    map[string]stubResult
	failures   map[string]stubResult
	stdinCalls []stdinRecord
}

// stdinRecord captures one RunWithStdin invocation for assertions.
type stdinRecord struct {
	cmd   string
	stdin []byte
}

type stubResult struct {
	out      []byte
	exitCode int
	err      error
}

func newStubSSHTransport() *stubSSHTransport {
	return &stubSSHTransport{
		outputs:  map[string]stubResult{},
		failures: map[string]stubResult{},
	}
}

// Dial satisfies SSHTransport. Counts dials per call (AC-06).
func (s *stubSSHTransport) Dial(_ context.Context, _ string, _ int, _ *credential.Credential) (SSHSession, error) {
	s.dialCount.Add(1)
	return &stubSession{parent: s}, nil
}

func (s *stubSSHTransport) DialCount() int64 { return s.dialCount.Load() }

// FailCommand makes cmd return stderr + exitCode > 0. AC-05.
func (s *stubSSHTransport) FailCommand(cmd, stderr string, exitCode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[cmd] = stubResult{out: []byte(stderr), exitCode: exitCode}
}

// SeedAll seeds canonical fixtures for every probe command Discover
// runs. Anything not seeded returns ("", 127, nil) — "command not found".
func (s *stubSSHTransport) SeedAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outputs["cat /etc/os-release"] = stubResult{out: []byte(rhel9OSRelease), exitCode: 0}
	s.outputs["uname -srvm"] = stubResult{out: []byte("Linux 5.14.0-362.el9.x86_64 #1 SMP Wed Aug 23 19:16:43 UTC 2025 x86_64\n"), exitCode: 0}
	s.outputs["cat /proc/meminfo"] = stubResult{out: []byte("MemTotal:        8011028 kB\nMemAvailable:    3567812 kB\nSwapTotal:       4194300 kB\n"), exitCode: 0}
	s.outputs["df -BG /"] = stubResult{out: []byte("Filesystem  1G-blocks  Used  Available  Use%  Mounted on\n/dev/sda1   50G        12G   38G        25%   /\n"), exitCode: 0}
	s.outputs["hostname"] = stubResult{out: []byte("rhel9-host.example.com\n"), exitCode: 0}
	s.outputs["hostname -f"] = stubResult{out: []byte("rhel9-host.example.com\n"), exitCode: 0}
	s.outputs["getenforce"] = stubResult{out: []byte("Enforcing\n"), exitCode: 0}
	s.outputs["aa-status --enabled"] = stubResult{out: nil, exitCode: 1}
	// Firewall probes left unseeded — tests that want a specific firewall
	// state seed it explicitly. Default is "no firewall detected" so the
	// AC-05 sudo-denied path stays clean.
}

const rhel9OSRelease = `NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
`

type stubSession struct{ parent *stubSSHTransport }

func (s *stubSession) Run(_ context.Context, cmd string) ([]byte, int, error) {
	s.parent.mu.Lock()
	defer s.parent.mu.Unlock()
	if r, ok := s.parent.failures[cmd]; ok {
		return r.out, r.exitCode, r.err
	}
	if r, ok := s.parent.outputs[cmd]; ok {
		return r.out, r.exitCode, r.err
	}
	return nil, 127, nil
}

// RunWithStdin satisfies the SSHSession interface added in
// system-ssh-connectivity v1.1.0. Same lookup map as Run; the stdin
// payload is captured for assertions.
func (s *stubSession) RunWithStdin(_ context.Context, cmd string, stdin []byte) ([]byte, int, error) {
	s.parent.mu.Lock()
	defer s.parent.mu.Unlock()
	s.parent.stdinCalls = append(s.parent.stdinCalls, stdinRecord{cmd: cmd, stdin: append([]byte(nil), stdin...)})
	if r, ok := s.parent.failures[cmd]; ok {
		return r.out, r.exitCode, r.err
	}
	if r, ok := s.parent.outputs[cmd]; ok {
		return r.out, r.exitCode, r.err
	}
	return nil, 127, nil
}

func (s *stubSession) Close() error { return nil }

// ---- stub event bus -------------------------------------------------------

type stubBus struct {
	mu   sync.Mutex
	seen []eventbus.EventKind
}

func newStubBus() *stubBus { return &stubBus{} }

func (b *stubBus) Publish(_ context.Context, ev eventbus.Event) {
	if ev == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seen = append(b.seen, ev.Kind())
}

func (b *stubBus) Saw(kind string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, k := range b.seen {
		if string(k) == kind {
			return true
		}
	}
	return false
}

// ---- audit recorder -------------------------------------------------------

type auditRecorder struct {
	mu     sync.Mutex
	counts map[audit.Code]int
}

func newAuditRecorder() *auditRecorder {
	return &auditRecorder{counts: map[audit.Code]int{}}
}

func (r *auditRecorder) Emit(_ context.Context, code audit.Code, _ audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[code]++
}

func (r *auditRecorder) CountFor(code string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[audit.Code(code)]
}
