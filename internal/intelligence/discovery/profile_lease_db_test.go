// @spec system-connection-profile

package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/queue"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
)

// @ac AC-14
// AC-14: OS discovery records what it learned about reaching a host (SSH
// auth method and sudo mode) only with its results, under its job lease. A
// run that lost its job leaves a newer profile untouched.
func TestDiscover_ProfileLearningIsLeased(t *testing.T) {
	t.Run("system-connection-profile/AC-14", func(t *testing.T) {
		pool, hostID, credSvc := freshDBHost(t)
		ctx := context.Background()
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE job_queue"); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		store := connprofile.NewStore(pool)

		// The session this run sees confirms NOPASSWD sudo, and the dial
		// reports that a password authenticated.
		stub := newStubSSHTransport()
		stub.SeedAll()
		stub.outputs["sudo -n ufw status"] = stubResult{out: []byte("Status: active\n"), exitCode: 0}

		var onDial func(ctx context.Context)
		tr := NewSSHTransport(owssh.ModeTOFU, owssh.NewMemoryStore()).WithProfiles(store)
		tr.dial = func(c context.Context, h string, p int, cred *credential.Credential, opts owssh.DialOptions) (SSHSession, error) {
			if onDial != nil {
				onDial(c)
			}
			if opts.ObservedAuth != nil {
				*opts.ObservedAuth = "password"
			}
			return stub.Dial(c, h, p, cred)
		}
		svc := NewService(pool, nil, nil).
			WithHostLookup(PoolHostLookup{Pool: pool}).
			WithCredentialService(credSvc).
			WithSSHTransport(tr).
			WithProfiles(store)

		// A run whose job is retired while it dials, after which another
		// run records a newer profile.
		l := claimLease(t, pool, hostID)
		onDial = func(c context.Context) {
			if _, err := pool.Exec(c,
				`UPDATE job_queue SET locked_at = now() - make_interval(secs => $2) WHERE id = $1`,
				l.JobID, (StaleDeadline + time.Minute).Seconds()); err != nil {
				t.Errorf("backdate: %v", err)
			}
			if n, err := RetireStaleJobs(c, pool, time.Now()); err != nil || n != 1 {
				t.Errorf("retire: n=%d err=%v", n, err)
			}
			if err := connprofile.Upsert(c, pool, hostID, connprofile.AuthKey, connprofile.SudoRoot); err != nil {
				t.Errorf("record newer profile: %v", err)
			}
		}
		if _, err := svc.Discover(ctx, hostID, l); !errors.Is(err, queue.ErrLeaseLost) {
			t.Fatalf("retired run: %v, want queue.ErrLeaseLost", err)
		}
		p, err := store.Get(ctx, hostID)
		if err != nil {
			t.Fatalf("get profile: %v", err)
		}
		if p.SSHAuthMethod != connprofile.AuthKey || p.SudoMode != connprofile.SudoRoot {
			t.Fatalf("retired run changed the profile to %+v, want key/root", p)
		}

		// A run that keeps its job records both observations.
		onDial = nil
		if _, err := pool.Exec(ctx, "DELETE FROM host_discovery_backoff"); err != nil {
			t.Fatalf("clear backoff: %v", err)
		}
		l = claimLease(t, pool, hostID)
		if _, err := svc.Discover(ctx, hostID, l); err != nil {
			t.Fatalf("leased run: %v", err)
		}
		p, err = store.Get(ctx, hostID)
		if err != nil {
			t.Fatalf("get profile: %v", err)
		}
		if p.SSHAuthMethod != connprofile.AuthPassword || p.SudoMode != connprofile.SudoNopasswd {
			t.Fatalf("leased run recorded %+v, want password/nopasswd", p)
		}
	})
}
