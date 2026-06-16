// @spec system-connection-profile
//
// AC traceability (this file):
//
//   AC-08  TestSSHTransportProd_AuthLearning
//
// The dial seam is stubbed so the auth-learning wiring (PreferAuth in,
// ObservedAuth out, RecordSSHAuth on success) is exercised without a real
// SSH server. The shared discovery prod transport is the one path both OS
// discovery and OS intelligence (collector) dial through.

package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/credential"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
)

// recordingProfiles is an in-memory connprofile store for the test.
type recordingProfiles struct {
	prefer   connprofile.SSHAuthMethod
	getErr   error
	gotID    uuid.UUID
	recorded connprofile.SSHAuthMethod
}

func (p *recordingProfiles) Get(_ context.Context, hostID uuid.UUID) (connprofile.Profile, error) {
	p.gotID = hostID
	if p.getErr != nil {
		return connprofile.Profile{}, p.getErr
	}
	return connprofile.Profile{SSHAuthMethod: p.prefer}, nil
}

func (p *recordingProfiles) RecordSSHAuth(_ context.Context, _ uuid.UUID, m connprofile.SSHAuthMethod) error {
	p.recorded = m
	return nil
}

func TestSSHTransportProd_AuthLearning(t *testing.T) {
	cred := &credential.Credential{Username: "u", AuthMethod: credential.AuthBoth, Password: "p"}

	// stubDial captures the PreferAuth handed down and simulates the
	// observed method crypto/ssh would report on a successful handshake.
	newStubDial := func(gotPrefer *string, simulateObserved string) func(context.Context, string, int, *credential.Credential, owssh.DialOptions) (SSHSession, error) {
		return func(_ context.Context, _ string, _ int, _ *credential.Credential, opts owssh.DialOptions) (SSHSession, error) {
			*gotPrefer = opts.PreferAuth
			if opts.ObservedAuth != nil {
				*opts.ObservedAuth = simulateObserved
			}
			return learnStubSession{}, nil
		}
	}

	t.Run("system-connection-profile/AC-08", func(t *testing.T) {
		hostID := uuid.Must(uuid.NewV7())
		profiles := &recordingProfiles{prefer: connprofile.AuthPassword}
		var gotPrefer string

		tr := NewSSHTransport(owssh.ModeTOFU, owssh.NewMemoryStore()).WithProfiles(profiles)
		tr.dial = newStubDial(&gotPrefer, "password")

		ctx := connprofile.WithHostID(context.Background(), hostID)
		if _, err := tr.Dial(ctx, "192.0.2.1", 22, cred); err != nil {
			t.Fatalf("dial: %v", err)
		}
		if gotPrefer != "password" {
			t.Errorf("lead-with: want PreferAuth=password, got %q", gotPrefer)
		}
		if profiles.gotID != hostID {
			t.Errorf("lookup: want Get(%s), got Get(%s)", hostID, profiles.gotID)
		}
		if profiles.recorded != connprofile.AuthPassword {
			t.Errorf("record: want recorded=password, got %q", profiles.recorded)
		}
	})

	t.Run("no host id on ctx: no learning", func(t *testing.T) {
		profiles := &recordingProfiles{prefer: connprofile.AuthPassword}
		var gotPrefer string

		tr := NewSSHTransport(owssh.ModeTOFU, owssh.NewMemoryStore()).WithProfiles(profiles)
		tr.dial = newStubDial(&gotPrefer, "key")

		if _, err := tr.Dial(context.Background(), "192.0.2.1", 22, cred); err != nil {
			t.Fatalf("dial: %v", err)
		}
		if gotPrefer != "" {
			t.Errorf("no host id: want empty PreferAuth, got %q", gotPrefer)
		}
		if profiles.recorded != "" {
			t.Errorf("no host id: want no record, got %q", profiles.recorded)
		}
	})

	t.Run("no store wired: no learning", func(t *testing.T) {
		var gotPrefer string
		tr := NewSSHTransport(owssh.ModeTOFU, owssh.NewMemoryStore())
		tr.dial = newStubDial(&gotPrefer, "key")

		ctx := connprofile.WithHostID(context.Background(), uuid.Must(uuid.NewV7()))
		if _, err := tr.Dial(ctx, "192.0.2.1", 22, cred); err != nil {
			t.Fatalf("dial: %v", err)
		}
		if gotPrefer != "" {
			t.Errorf("no store: want empty PreferAuth, got %q", gotPrefer)
		}
	})

	t.Run("profile lookup error is non-fatal", func(t *testing.T) {
		profiles := &recordingProfiles{getErr: errors.New("db down")}
		var gotPrefer string

		tr := NewSSHTransport(owssh.ModeTOFU, owssh.NewMemoryStore()).WithProfiles(profiles)
		tr.dial = newStubDial(&gotPrefer, "password")

		ctx := connprofile.WithHostID(context.Background(), uuid.Must(uuid.NewV7()))
		if _, err := tr.Dial(ctx, "192.0.2.1", 22, cred); err != nil {
			t.Fatalf("dial: want success despite lookup error, got %v", err)
		}
		if gotPrefer != "" {
			t.Errorf("lookup error: want default order (empty PreferAuth), got %q", gotPrefer)
		}
		// observed still recorded — learning continues even when the
		// lead-with hint was unavailable.
		if profiles.recorded != connprofile.AuthPassword {
			t.Errorf("record: want recorded=password, got %q", profiles.recorded)
		}
	})
}

// learnStubSession is a no-op SSHSession for the dial-seam tests.
type learnStubSession struct{}

func (learnStubSession) Run(context.Context, string) ([]byte, int, error) { return nil, 0, nil }
func (learnStubSession) RunWithStdin(context.Context, string, []byte) ([]byte, int, error) {
	return nil, 0, nil
}
func (learnStubSession) Close() error { return nil }
