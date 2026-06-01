package collector

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

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return correlation.Set(ctx, uuid.NewString())
}

func testHostFacts() hostFacts {
	return hostFacts{
		HostID: uuid.MustParse("00000000-0000-0000-0000-000000000002"),
		Addr:   "test.local",
		Port:   22,
		Cred:   nil,
	}
}

// ---- stub SSH transport ---------------------------------------------------

type stubSSHTransport struct {
	mu        sync.Mutex
	dialCount atomic.Int64
	outputs   map[string]stubResult
	failures  map[string]stubResult
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

func (s *stubSSHTransport) Dial(_ context.Context, _ string, _ int, _ *credential.Credential) (SSHSession, error) {
	s.dialCount.Add(1)
	return &stubSession{parent: s}, nil
}

func (s *stubSSHTransport) DialCount() int64 { return s.dialCount.Load() }

func (s *stubSSHTransport) FailCommand(cmd, stderr string, exitCode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[cmd] = stubResult{out: []byte(stderr), exitCode: exitCode}
}

func (s *stubSSHTransport) SeedAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outputs["cat /etc/passwd"] = stubResult{out: []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:alice:/home/alice:/bin/bash\n"), exitCode: 0}
	s.outputs["sudo -n cat /etc/shadow"] = stubResult{out: []byte("root:$6$abc:19000:0:99999:7:::\nalice:!!:19500:0:99999:7:::\n"), exitCode: 0}
	s.outputs["getent group"] = stubResult{out: []byte("root:x:0:root\nwheel:x:10:root,alice\n"), exitCode: 0}
	s.outputs["ss -tln"] = stubResult{
		out:      []byte("State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port\nLISTEN   0        128              0.0.0.0:22              0.0.0.0:*\n"),
		exitCode: 0,
	}
	s.outputs["rpm -qa --queryformat='%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null || dpkg -l 2>/dev/null"] = stubResult{
		out:      []byte("openssh 9.0p1-19\nglibc 2.34-83.el9\n"),
		exitCode: 0,
	}
	s.outputs["systemctl list-units --type=service --all --no-legend --plain"] = stubResult{
		out:      []byte("sshd.service loaded active running OpenSSH server daemon\n"),
		exitCode: 0,
	}
	s.outputs["uname -r"] = stubResult{out: []byte("5.14.0-362.el9.x86_64\n"), exitCode: 0}
	s.outputs["test -f /var/run/reboot-required || test -f /run/reboot-required"] = stubResult{exitCode: 1}
	s.outputs["cat /proc/uptime"] = stubResult{out: []byte("123456.78 50000.00\n"), exitCode: 0}
	s.outputs["cat /proc/mounts"] = stubResult{out: []byte("/dev/sda1 / ext4 rw 0 0\n"), exitCode: 0}
	s.outputs["sha256sum /etc/sudoers"] = stubResult{out: []byte("aaaa1234 /etc/sudoers\n"), exitCode: 0}
	s.outputs["sha256sum /etc/ssh/sshd_config"] = stubResult{out: []byte("bbbb5678 /etc/ssh/sshd_config\n"), exitCode: 0}
	s.outputs["sha256sum /etc/passwd"] = stubResult{out: []byte("cccc9012 /etc/passwd\n"), exitCode: 0}
	s.outputs["sudo -n sha256sum /etc/shadow"] = stubResult{out: []byte("dddd3456 /etc/shadow\n"), exitCode: 0}
}

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

func (s *stubSession) Close() error { return nil }

// ---- stub event bus -------------------------------------------------------

type stubBus struct {
	mu   sync.Mutex
	seen []eventbus.Event
}

func newStubBus() *stubBus { return &stubBus{} }

func (b *stubBus) Publish(_ context.Context, ev eventbus.Event) {
	if ev == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seen = append(b.seen, ev)
}

func (b *stubBus) Saw(kind eventbus.EventKind) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range b.seen {
		if e.Kind() == kind {
			return true
		}
	}
	return false
}

func (b *stubBus) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.seen)
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

func (r *auditRecorder) CountFor(code audit.Code) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[code]
}

// Avoid unused import lints in skeletal helpers.
var _ = newStubBus
var _ = newAuditRecorder
