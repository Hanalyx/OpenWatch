// @spec system-credential-protection
//
// Protection state and reservations against PostgreSQL, with a controlled
// clock and process table. Examples B to H are those of contract r2,
// section 18 (features/OW-122).

package credprotect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// @ac AC-01
// AC-01: resolution, root ancestry, example B, and a directory identity for
// another username refused.
func TestResolution(t *testing.T) {
	t.Run("system-credential-protection/AC-01", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h1, h2 := f.host(), f.host()
		a, b := f.cred("ops"), f.cred("  OPS ")
		root := f.identity(a, h1)
		for _, got := range []uuid.UUID{f.identity(a, h2), f.identity(b, h1)} {
			if got != root {
				t.Fatalf("an unconfirmed credential resolved to %v, not the root %v", got, root)
			}
		}
		l1, l2 := f.cred("ops"), f.cred("ops")
		for _, c := range []uuid.UUID{l1, l2} {
			if err := f.store.Classify(ctx, c, Target{Scope: ScopeLocal}); err != nil {
				t.Fatalf("classify local: %v", err)
			}
		}
		if f.identity(l1, h1) != f.identity(l2, h1) {
			t.Fatal("two local credentials for one account on one host resolved to different identities")
		}
		if f.identity(l1, h1) == f.identity(l1, h2) || f.identity(l1, h1) == root {
			t.Fatal("a local credential did not resolve per host")
		}
		dir, err := f.store.CreateDirectory(ctx, "corp", "ops")
		if err != nil {
			t.Fatalf("create directory: %v", err)
		}
		d := f.cred("ops")
		if err := f.store.Classify(ctx, d, Target{Scope: ScopeDirectory, Directory: dir}); err != nil {
			t.Fatalf("classify directory: %v", err)
		}
		if f.identity(d, h1) != dir {
			t.Fatal("a directory credential did not resolve to its directory identity")
		}
		for _, id := range []uuid.UUID{f.identity(l1, h1), dir} {
			if !f.hasAncestor(id, root) {
				t.Fatalf("the root is not an ancestor of %v", id)
			}
		}
		other := f.cred("svc")
		f.wantRefused(f.store.Classify(ctx, other, Target{Scope: ScopeDirectory, Directory: dir}), ErrClassification)

		// Example B: a block on the root reaches a credential created as
		// local afterwards, on a host it was never used on.
		p1 := pw(1)
		f.block(a, h1, p1)
		h3 := f.host()
		r2 := f.cred("ops")
		if err := f.store.Classify(ctx, r2, Target{Scope: ScopeLocal}); err != nil {
			t.Fatalf("classify: %v", err)
		}
		for _, k := range []Kind{KindOrdinary, KindVerification} {
			_, err := f.store.Reserve(ctx, f.req(r2, h3, p1, k))
			f.wantRefused(err, ErrBlocked)
		}
	})
}

func (f *fixture) hasAncestor(id, want uuid.UUID) bool {
	f.t.Helper()
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	ids, err := ancestors(context.Background(), tx, id)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, a := range ids {
		if a == want {
			return true
		}
	}
	return false
}

func (f *fixture) depth(id uuid.UUID) int {
	return f.count(`SELECT depth FROM credprotect_identities WHERE id = $1`, id)
}

// @ac AC-02
// AC-02: classification moves only downward, within depth 3.
func TestClassificationPaths(t *testing.T) {
	t.Run("system-credential-protection/AC-02", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		dir, err := f.store.CreateDirectory(ctx, "corp", "ops")
		if err != nil {
			t.Fatal(err)
		}
		dir2, err := f.store.CreateDirectory(ctx, "corp2", "ops")
		if err != nil {
			t.Fatal(err)
		}
		local := f.cred("ops")
		if err := f.store.Classify(ctx, local, Target{Scope: ScopeLocal}); err != nil {
			t.Fatalf("unconfirmed to local: %v", err)
		}
		if got := f.depth(f.identity(local, h)); got != 2 {
			t.Fatalf("a local identity below the root has depth %d, want 2", got)
		}
		viaDir := f.cred("ops")
		if err := f.store.Classify(ctx, viaDir, Target{Scope: ScopeDirectory, Directory: dir}); err != nil {
			t.Fatalf("unconfirmed to directory: %v", err)
		}
		if got := f.depth(dir); got != 2 {
			t.Fatalf("directory depth %d, want 2", got)
		}
		if err := f.store.Classify(ctx, viaDir, Target{Scope: ScopeLocal}); err != nil {
			t.Fatalf("directory to local: %v", err)
		}
		h2 := f.host()
		if got := f.depth(f.identity(viaDir, h2)); got != 3 {
			t.Fatalf("a local identity below a directory has depth %d, want 3", got)
		}
		dirOnly := f.cred("ops")
		if err := f.store.Classify(ctx, dirOnly, Target{Scope: ScopeDirectory, Directory: dir}); err != nil {
			t.Fatal(err)
		}
		before := f.count(`SELECT count(*) FROM credprotect_credential_classes`)
		for name, c := range map[string]struct {
			cred uuid.UUID
			to   Target
		}{
			"directory to directory":   {dirOnly, Target{Scope: ScopeDirectory, Directory: dir2}},
			"local to directory":       {local, Target{Scope: ScopeDirectory, Directory: dir}},
			"local to local":           {local, Target{Scope: ScopeLocal}},
			"local to unconfirmed":     {local, Target{Scope: ScopeUnconfirmed}},
			"directory to unconfirmed": {dirOnly, Target{Scope: ScopeUnconfirmed}},
		} {
			t.Run(name, func(t *testing.T) {
				f.wantRefused(f.store.Classify(ctx, c.cred, c.to), ErrClassification)
			})
		}
		if after := f.count(`SELECT count(*) FROM credprotect_credential_classes`); after != before {
			t.Fatal("a refused classification changed a classification")
		}
	})
}

// @ac AC-03
// AC-03: one state per secret across stages; aliases; no identifier in an
// error or a log line.
func TestOneStatePerSecretAcrossStages(t *testing.T) {
	t.Run("system-credential-protection/AC-03", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		p1, p2 := pw(1), pw(2)
		f.block(c, h, p1) // rejected at the ssh stage
		sudo := f.req(c, h, p1, KindOrdinary)
		sudo.Stage = "sudo"
		_, err := f.store.Reserve(ctx, sudo)
		f.wantRefused(err, ErrBlocked)

		// The reverse: rejected at the sudo stage refuses ssh.
		f.activate(c, h, p2)
		r := f.req(c, h, p2, KindOrdinary)
		r.Stage = "sudo"
		sub, err := f.store.Reserve(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		f.settle(sub.ID, OutcomeRejected)
		_, err = f.store.Reserve(ctx, f.req(c, h, p2, KindOrdinary))
		f.wantRefused(err, ErrBlocked)

		// Any alias matches: P1 under a second key id as well.
		var k2 Alias
		k2.KeyID = "k2"
		k2.ID[0] = 9
		both := Secret{Kind: SecretPassword, Aliases: []Alias{k2, p1.Aliases[0]}}
		f.wantMode(c, h, both, ModeBlocked)
		// A different secret of the same identity is not blocked.
		f.wantMode(c, h, pw(3), ModeVerifying)

		// No identifier in an error or a log line.
		var logs bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		t.Cleanup(func() { slog.SetDefault(prev) })
		var msgs []string
		_, err = f.store.Reserve(ctx, f.req(c, h, p1, KindOrdinary))
		msgs = append(msgs, err.Error())
		sub3 := f.reserve(c, h, pw(3), KindVerification)
		f.settle(sub3.ID, OutcomeRejected)
		if _, err := f.store.Settle(ctx, sub3.ID, OutcomeVerified); err == nil {
			t.Fatal("a conflicting outcome was accepted")
		} else {
			msgs = append(msgs, err.Error())
		}
		err = f.store.Fence(ctx, sub3.ID, Current{Active: true, Secret: p1})
		msgs = append(msgs, err.Error(), fmt.Sprintf("%v %+v %#v", p1, p1, p1), logs.String())
		if !strings.Contains(logs.String(), "conflicting outcome") {
			t.Fatalf("the conflict was not logged: %q", logs.String())
		}
		for _, s := range []Secret{p1, pw(3)} {
			id := s.Aliases[0].ID
			for _, enc := range []string{hex.EncodeToString(id[:]), base64.StdEncoding.EncodeToString(id[:]),
				base64.RawStdEncoding.EncodeToString(id[:]), string(id[:])} {
				for _, m := range msgs {
					if strings.Contains(m, enc) {
						t.Fatalf("an identifier appears in %q", m)
					}
				}
			}
		}
	})
}

// @ac AC-04
// AC-04: modes.
func TestModes(t *testing.T) {
	t.Run("system-credential-protection/AC-04", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.wantMode(c, h, p1, ModeVerifying)
		f.activate(c, h, p1)
		f.block(c, h, p1)
		f.wantMode(c, h, p1, ModeBlocked)
		root := f.identity(c, h)
		if _, err := f.store.RequestVerification(ctx, root, p1, f.user); err != nil {
			t.Fatal(err)
		}
		f.wantMode(c, h, p1, ModeVerifying)

		// A pause on the root reaches a local child; ending "it" on the
		// child ends nothing.
		lc := f.cred("ops")
		if err := f.store.Classify(ctx, lc, Target{Scope: ScopeLocal}); err != nil {
			t.Fatal(err)
		}
		child := f.identity(lc, h)
		if _, err := f.store.Pause(ctx, root, "maintenance"); err != nil {
			t.Fatal(err)
		}
		f.wantMode(lc, h, pw(5), ModePaused)
		if n, err := f.store.EndPause(ctx, child); err != nil || n != 0 {
			t.Fatalf("EndPause on the child ended %d pauses (%v)", n, err)
		}
		f.wantMode(lc, h, pw(5), ModePaused)
		if n, err := f.store.EndPause(ctx, root); err != nil || n != 1 {
			t.Fatalf("EndPause on the root ended %d (%v)", n, err)
		}
		f.wantMode(lc, h, pw(5), ModeVerifying)

		// A cooldown applies until it expires.
		p6 := pw(6)
		sub := f.reserve(c, h, p6, KindVerification)
		f.settle(sub.ID, OutcomeUnsuccessful)
		f.wantRefused(f.requestErr(root, p6), ErrCooldown)
		f.clock.Advance(Cooldown)
		f.wantRefused(f.requestErr(root, p6), ErrAllowanceUsed)
	})
}

func (f *fixture) requestErr(identity uuid.UUID, s Secret) error {
	_, err := f.store.RequestVerification(context.Background(), identity, s, f.user)
	return err
}

// @ac AC-05
// AC-05: reservation rules, snapshots, races and an unreachable store.
func TestReservation(t *testing.T) {
	t.Run("system-credential-protection/AC-05", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		p1 := pw(1)
		_, err := f.store.Reserve(ctx, f.req(c, h, p1, KindOrdinary))
		f.wantRefused(err, ErrVerifying)
		f.activate(c, h, p1)
		_, err = f.store.Reserve(ctx, f.req(c, h, p1, KindVerification))
		f.wantRefused(err, ErrNotVerifying)
		b1 := f.block(c, h, p1)
		_, err = f.store.Reserve(ctx, f.req(c, h, p1, KindOrdinary))
		f.wantRefused(err, ErrBlocked)
		root := f.identity(c, h)
		if _, err := f.store.RequestVerification(ctx, root, p1, f.user); err != nil {
			t.Fatal(err)
		}
		v := f.reserve(c, h, p1, KindVerification)
		if len(v.Snapshot) != 1 || v.Snapshot[0] != b1 {
			t.Fatalf("snapshot = %v, want [%v]", v.Snapshot, b1)
		}
		f.settle(v.ID, OutcomeVerified)

		t.Run("eight workers race for one identity", func(t *testing.T) {
			got := race(8, func(int) error { _, err := f.store.Reserve(ctx, f.req(c, h, p1, KindOrdinary)); return err })
			if got[nil] != 1 || got[ErrSlotBusy] != 7 {
				t.Fatalf("results %v, want one reservation and seven ErrSlotBusy", got)
			}
		})

		t.Run("ordinary work racing a verification (example G)", func(t *testing.T) {
			g := newFixture(t)
			gh := g.host()
			gc := g.cred("ops")
			g.block(gc, gh, p1)
			if _, err := g.store.RequestVerification(ctx, g.identity(gc, gh), p1, g.user); err != nil {
				t.Fatal(err)
			}
			ordinaryBefore := g.count(`SELECT count(*) FROM credprotect_submissions WHERE kind = 'ordinary'`)
			got := race(9, func(i int) error {
				k := KindOrdinary
				if i == 4 {
					k = KindVerification
				}
				_, err := g.store.Reserve(ctx, g.req(gc, gh, p1, k))
				return err
			})
			if got[nil] != 1 || got[ErrVerifying] != 8 {
				t.Fatalf("results %v, want only the verification to reserve", got)
			}
			if n := g.count(`SELECT count(*) FROM credprotect_submissions WHERE kind = 'ordinary'`); n != ordinaryBefore {
				t.Fatalf("%d ordinary submissions were reserved while VERIFYING", n-ordinaryBefore)
			}
		})

		t.Run("store unreachable", func(t *testing.T) {
			closed, err := pgxpool.New(ctx, f.pool.Config().ConnString())
			if err != nil {
				t.Fatal(err)
			}
			closed.Close()
			before := f.count(`SELECT count(*) FROM credprotect_submissions`)
			s := New(closed, WithClock(f.clock), WithProcesses(f.procs))
			if _, err := s.Reserve(ctx, f.req(c, h, p1, KindOrdinary)); err == nil {
				t.Fatal("Reserve succeeded with the store unreachable")
			}
			if after := f.count(`SELECT count(*) FROM credprotect_submissions`); after != before {
				t.Fatal("a reservation was recorded")
			}
		})
	})
}

// race runs n calls at once and counts their errors by sentinel.
func race(n int, call func(int) error) map[error]int {
	var mu sync.Mutex
	got := map[error]int{}
	var wg sync.WaitGroup
	start := make(chan struct{})
	sentinels := []error{ErrSlotBusy, ErrVerifying, ErrBlocked, ErrOutcomeConflict}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			err := call(i)
			key := err
			for _, s := range sentinels {
				if errors.Is(err, s) {
					key = s
				}
			}
			mu.Lock()
			got[key]++
			mu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()
	return got
}

// @ac AC-06
// AC-06: the fence.
func TestFence(t *testing.T) {
	t.Run("system-credential-protection/AC-06", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.activate(c, h, p1)
		cur := Current{Active: true, Secret: p1}

		sub := f.reserve(c, h, p1, KindOrdinary)
		if err := f.store.Fence(ctx, sub.ID, cur); err != nil {
			t.Fatalf("the fence refused a valid submission: %v", err)
		}
		f.wantRefused(f.store.Fence(ctx, sub.ID, Current{Active: false, Secret: p1}), ErrFenceRefused)
		f.wantRefused(f.store.Fence(ctx, sub.ID, Current{Active: true, Secret: pw(2)}), ErrFenceRefused)
		f.clock.Advance(5 * time.Minute)
		f.wantRefused(f.store.Fence(ctx, sub.ID, cur), ErrFenceRefused)
		f.settle(sub.ID, OutcomeVerified) // late: releases the slot
		f.wantRefused(f.store.Fence(ctx, sub.ID, cur), ErrFenceRefused)

		// A block that appears after reserve: a local identity holds a
		// reservation while another identity's rejection blocks the root.
		lc := f.cred("ops")
		if err := f.store.Classify(ctx, lc, Target{Scope: ScopeLocal}); err != nil {
			t.Fatal(err)
		}
		f.activate(lc, h, p1)
		held := f.reserve(lc, h, p1, KindOrdinary)
		if err := f.store.Fence(ctx, held.ID, cur); err != nil {
			t.Fatalf("fence before the block: %v", err)
		}
		f.block(c, f.host(), p1)
		f.wantRefused(f.store.Fence(ctx, held.ID, cur), ErrFenceRefused)
	})
}

// @ac AC-07
// AC-07: recording is idempotent and conditional; late outcomes.
func TestRecording(t *testing.T) {
	t.Run("system-credential-protection/AC-07", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		p1, p2, p3 := pw(1), pw(2), pw(3)
		f.activate(c, h, p1)
		sub := f.reserve(c, h, p1, KindOrdinary)
		f.settle(sub.ID, OutcomeNotSubmitted)
		if res := f.settle(sub.ID, OutcomeNotSubmitted); !res.Duplicate {
			t.Fatal("a repeated outcome was not a no-op")
		}
		_, err := f.store.Settle(ctx, sub.ID, OutcomeRejected)
		f.wantRefused(err, ErrOutcomeConflict)
		if n := f.count(`SELECT count(*) FROM credprotect_restrictions WHERE submission_id = $1`, sub.ID); n != 0 {
			t.Fatal("a refused outcome had an effect")
		}

		// After expiry's unknown, the owner's outcome is recorded once, late.
		f.activate(c, h, p2)
		exp := f.reserve(c, h, p2, KindOrdinary)
		f.clock.Advance(6 * time.Minute)
		if n, err := f.store.Expire(ctx); err != nil || n != 1 {
			t.Fatalf("Expire = %d, %v", n, err)
		}
		if res := f.settle(exp.ID, OutcomeVerified); !res.Late {
			t.Fatal("the owner's outcome after expiry was not late")
		}
		if res := f.settle(exp.ID, OutcomeVerified); !res.Duplicate {
			t.Fatal("a repeated late outcome was not a no-op")
		}
		_, err = f.store.Settle(ctx, exp.ID, OutcomeRejected)
		f.wantRefused(err, ErrOutcomeConflict)

		// An outcome after the deadline, before any expiry, is late.
		f.activate(c, h, p3)
		slow := f.reserve(c, h, p3, KindOrdinary)
		f.clock.Advance(5 * time.Minute)
		if res := f.settle(slow.ID, OutcomeVerified); !res.Late {
			t.Fatal("an outcome after the deadline was not late")
		}

		// Concurrent duplicate settlements create one block.
		p4 := pw(4)
		f.activate(c, h, p4)
		dup := f.reserve(c, h, p4, KindOrdinary)
		got := race(8, func(int) error { _, err := f.store.Settle(ctx, dup.ID, OutcomeRejected); return err })
		if got[nil] != 8 {
			t.Fatalf("duplicate settlements: %v", got)
		}
		if n := f.count(`SELECT count(*) FROM credprotect_restrictions WHERE submission_id = $1`, dup.ID); n != 1 {
			t.Fatalf("%d blocks from one submission, want 1", n)
		}
	})
}

func (f *fixture) slotHeld(id uuid.UUID) bool {
	return f.count(`SELECT CASE WHEN slot_held THEN 1 ELSE 0 END FROM credprotect_submissions WHERE id = $1`, id) == 1
}

// @ac AC-08
// AC-08: slots, expiry, verified termination, override, and example D.
func TestSlots(t *testing.T) {
	t.Run("system-credential-protection/AC-08", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.activate(c, h, p1)
		root := f.identity(c, h)

		// Example D. W1 passes the fence and stalls.
		w1 := f.reserve(c, h, p1, KindOrdinary)
		if err := f.store.Fence(ctx, w1.ID, Current{Active: true, Secret: p1}); err != nil {
			t.Fatal(err)
		}
		f.clock.Advance(6 * time.Minute)
		if _, err := f.store.Expire(ctx); err != nil {
			t.Fatal(err)
		}
		f.wantMode(c, h, p1, ModeBlocked)
		if !f.slotHeld(w1.ID) {
			t.Fatal("expiry released the slot")
		}
		// W1's process on another machine cannot be verified ended.
		f.procs.kill(4242)
		f.setOwnerMachine(w1.ID, "m2")
		_, err := f.store.ReleaseIfTerminated(ctx, w1.ID)
		f.wantRefused(err, ErrNotTerminated)
		f.wantRefused(f.store.Override(ctx, w1.ID, f.user, "", true), ErrOverride)
		f.wantRefused(f.store.Override(ctx, w1.ID, f.user, "host unreachable", false), ErrOverride)
		if err := f.store.Override(ctx, w1.ID, f.user, "host unreachable", true); err != nil {
			t.Fatal(err)
		}
		if st := f.status(root, p1); st.K+st.O != 2 {
			t.Fatalf("bound K + o = %d, want 2", st.K+st.O)
		}
		if _, err := f.store.RequestVerification(ctx, root, p1, f.user); err != nil {
			t.Fatal(err)
		}
		v := f.reserve(c, h, p1, KindVerification)
		if res := f.settle(v.ID, OutcomeVerified); res.Recovery == uuid.Nil {
			t.Fatal("the verification did not recover")
		}
		f.wantMode(c, h, p1, ModeActive)
		// W1 reports late: it is the o, and o returns to 0.
		if res := f.settle(w1.ID, OutcomeVerified); !res.Late || !res.Released {
			t.Fatalf("W1's late report: %+v", res)
		}
		if st := f.status(root, p1); st.O != 0 {
			t.Fatalf("o = %d after W1 reported, want 0", st.O)
		}

		// Verified termination on this machine: a living owner keeps the
		// slot; a dead one releases it, recording unknown first.
		f.procs.alive[4242] = "100"
		p2 := pw(2)
		f.activate(c, h, p2)
		s2 := f.reserve(c, h, p2, KindOrdinary)
		_, err = f.store.ReleaseIfTerminated(ctx, s2.ID)
		f.wantRefused(err, ErrNotTerminated)
		f.procs.alive[4242] = "999" // the PID was reused by another process
		res, err := f.store.ReleaseIfTerminated(ctx, s2.ID)
		if err != nil || !res.Released || len(res.Blocks) != 1 {
			t.Fatalf("termination: %+v, %v", res, err)
		}
		if f.slotHeld(s2.ID) {
			t.Fatal("termination did not release the slot")
		}
		f.wantMode(c, h, p2, ModeBlocked)
	})
}

func (f *fixture) setOwnerMachine(id uuid.UUID, m string) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE credprotect_submissions SET owner_machine = $2 WHERE id = $1`, id, m); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) status(identity uuid.UUID, s Secret) Status {
	f.t.Helper()
	st, err := f.store.Status(context.Background(), identity, s)
	if err != nil {
		f.t.Fatal(err)
	}
	return st
}

// @ac AC-09
// AC-09: restrictive effects.
func TestRestrictiveEffects(t *testing.T) {
	t.Run("system-credential-protection/AC-09", func(t *testing.T) {
		for _, o := range []Outcome{OutcomeRejected, OutcomeUnsuccessful, OutcomeUnknown, OutcomeUnsupportedProfile} {
			t.Run(string(o), func(t *testing.T) {
				f := newFixture(t)
				h := f.host()
				c := f.cred("ops")
				p1, p2 := pw(1), pw(2)
				f.activate(c, h, p1)
				f.activate(c, h, p2)
				sub := f.reserve(c, h, p1, KindOrdinary)
				if res := f.settle(sub.ID, o); len(res.Blocks) != 1 {
					t.Fatalf("%s created %d blocks", o, len(res.Blocks))
				}
				f.wantMode(c, h, p1, ModeBlocked)
				f.wantMode(c, h, p2, ModeActive)
			})
		}
		t.Run("ambiguous blocks every secret", func(t *testing.T) {
			f := newFixture(t)
			h := f.host()
			c := f.cred("ops")
			p1, p2 := pw(1), pw(2)
			f.activate(c, h, p1)
			f.activate(c, h, p2)
			sub := f.reserve(c, h, p1, KindOrdinary)
			f.settle(sub.ID, OutcomeAmbiguous)
			f.wantMode(c, h, p1, ModeBlocked)
			f.wantMode(c, h, p2, ModeBlocked)
			f.wantMode(c, h, pw(9), ModeBlocked)
		})
		for _, o := range []Outcome{OutcomeNotSubmitted, OutcomeLocalDecryptFailed} {
			t.Run(string(o)+" changes nothing", func(t *testing.T) {
				f := newFixture(t)
				h := f.host()
				c := f.cred("ops")
				f.activate(c, h, pw(1))
				sub := f.reserve(c, h, pw(1), KindOrdinary)
				f.settle(sub.ID, o)
				if n := f.count(`SELECT count(*) FROM credprotect_restrictions`); n != 0 {
					t.Fatalf("%s created %d restrictions", o, n)
				}
				f.wantMode(c, h, pw(1), ModeActive)
			})
		}
		t.Run("a late failure of an old secret does not block a new one", func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			h := f.host()
			c := f.cred("ops")
			p1, p2 := pw(1), pw(2)
			f.activate(c, h, p1)
			old := f.reserve(c, h, p1, KindOrdinary)
			f.clock.Advance(6 * time.Minute)
			if _, err := f.store.Expire(ctx); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Override(ctx, old.ID, f.user, "rotated", true); err != nil {
				t.Fatal(err)
			}
			f.activate(c, h, p2)
			f.settle(old.ID, OutcomeRejected)
			f.wantMode(c, h, p2, ModeActive)
			f.wantMode(c, h, p1, ModeBlocked)
		})
		t.Run("a non-verified verification starts a cooldown and uses the allowance", func(t *testing.T) {
			f := newFixture(t)
			h := f.host()
			c := f.cred("ops")
			sub := f.reserve(c, h, pw(1), KindVerification)
			f.settle(sub.ID, OutcomeRejected)
			for _, k := range []string{"block", "cooldown", "allowance_used"} {
				if n := f.count(`SELECT count(*) FROM credprotect_restrictions WHERE submission_id = $1 AND kind = $2`,
					sub.ID, k); n != 1 {
					t.Fatalf("%d %s restrictions, want 1", n, k)
				}
			}
		})
	})
}

// @ac AC-10
// AC-10: permissive effects need an exact match.
func TestExactMatch(t *testing.T) {
	t.Run("system-credential-protection/AC-10", func(t *testing.T) {
		setup := func(t *testing.T) (*fixture, uuid.UUID, uuid.UUID, Submission) {
			f := newFixture(t)
			h := f.host()
			c := f.cred("ops")
			f.block(c, h, pw(1))
			if _, err := f.store.RequestVerification(context.Background(), f.identity(c, h), pw(1), f.user); err != nil {
				t.Fatal(err)
			}
			return f, c, h, f.reserve(c, h, pw(1), KindVerification)
		}
		t.Run("unchanged: recovery", func(t *testing.T) {
			f, c, h, v := setup(t)
			res := f.settle(v.ID, OutcomeVerified)
			if res.Recovery == uuid.Nil {
				t.Fatal("no recovery on an exact match")
			}
			if n := f.count(`SELECT cardinality(lifted) FROM credprotect_recoveries WHERE id = $1`, res.Recovery); n != 1 {
				t.Fatalf("the recovery lifts %d blocks, want the snapshot's 1", n)
			}
			f.wantMode(c, h, pw(1), ModeActive)
		})
		t.Run("a pause began during the attempt", func(t *testing.T) {
			f, c, h, v := setup(t)
			root := f.identity(c, h)
			if _, err := f.store.Pause(context.Background(), root, "change freeze"); err != nil {
				t.Fatal(err)
			}
			if res := f.settle(v.ID, OutcomeVerified); res.Recovery != uuid.Nil {
				t.Fatal("recovered during a pause")
			}
			f.wantMode(c, h, pw(1), ModePaused)
			if _, err := f.store.EndPause(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			f.wantMode(c, h, pw(1), ModeVerifying) // example G: the request stands; a new verification is needed
		})
		t.Run("a block appeared after reserve (example H)", func(t *testing.T) {
			// The verification runs on a local identity; a new block on its
			// root, from another identity's ambiguous outcome, is not in the
			// verification's snapshot.
			f := newFixture(t)
			ctx := context.Background()
			h := f.host()
			c := f.cred("ops")
			if err := f.store.Classify(ctx, c, Target{Scope: ScopeLocal}); err != nil {
				t.Fatal(err)
			}
			f.block(c, h, pw(1))
			if _, err := f.store.RequestVerification(ctx, f.identity(c, h), pw(1), f.user); err != nil {
				t.Fatal(err)
			}
			v := f.reserve(c, h, pw(1), KindVerification)
			f.addBlockOnRoot(c, h)
			if res := f.settle(v.ID, OutcomeVerified); res.Recovery != uuid.Nil {
				t.Fatal("recovered although the applicable set changed")
			}
			if n := f.count(`SELECT count(*) FROM credprotect_restrictions WHERE kind = 'allowance_used'`); n != 0 {
				t.Fatal("a verified outcome used the allowance")
			}
		})
		t.Run("late", func(t *testing.T) {
			f, c, h, v := setup(t)
			f.clock.Advance(5 * time.Minute)
			if res := f.settle(v.ID, OutcomeVerified); res.Recovery != uuid.Nil {
				t.Fatal("a late verified outcome recovered")
			}
			f.wantMode(c, h, pw(1), ModeVerifying)
		})
		t.Run("ordinary", func(t *testing.T) {
			f := newFixture(t)
			h := f.host()
			c := f.cred("ops")
			f.activate(c, h, pw(1))
			before := f.count(`SELECT count(*) FROM credprotect_recoveries`)
			s := f.reserve(c, h, pw(1), KindOrdinary)
			if res := f.settle(s.ID, OutcomeVerified); res.Recovery != uuid.Nil {
				t.Fatal("an ordinary submission recovered")
			}
			if f.count(`SELECT count(*) FROM credprotect_recoveries`) != before {
				t.Fatal("a recovery row was written")
			}
		})
	})
}

// addBlockOnRoot blocks every secret on the root of "ops", by an ambiguous
// outcome from an unconfirmed credential on a fresh secret. The caller's
// identity must not be the root, whose slot this needs.
func (f *fixture) addBlockOnRoot(_, _ uuid.UUID) {
	f.t.Helper()
	rc := f.cred("ops")
	rh := f.host()
	f.activate(rc, rh, pw(8))
	s := f.reserve(rc, rh, pw(8), KindOrdinary)
	f.settle(s.ID, OutcomeAmbiguous)
}

// @ac AC-11
// AC-11: recovery through lineage, examples E, F and H.
func TestRecoveryThroughLineage(t *testing.T) {
	t.Run("system-credential-protection/AC-11", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h1, h2, h4 := f.host(), f.host(), f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.activate(c, h1, p1)
		b1 := f.block(c, h1, p1) // E: W rejected, block B1 on the root
		if err := f.store.Classify(ctx, c, Target{Scope: ScopeLocal}); err != nil {
			t.Fatal(err)
		}
		f.wantMode(c, h1, p1, ModeBlocked)
		f.wantMode(c, h2, p1, ModeBlocked)

		// F: verification on (H1, ops) lifts B1 there only.
		i1 := f.identity(c, h1)
		if _, err := f.store.RequestVerification(ctx, i1, p1, f.user); err != nil {
			t.Fatal(err)
		}
		v := f.reserve(c, h1, p1, KindVerification)
		if len(v.Snapshot) != 1 || v.Snapshot[0] != b1 {
			t.Fatalf("snapshot %v, want [B1]", v.Snapshot)
		}
		if res := f.settle(v.ID, OutcomeVerified); res.Recovery == uuid.Nil {
			t.Fatal("no recovery")
		}
		f.wantMode(c, h1, p1, ModeActive)
		f.wantMode(c, h2, p1, ModeBlocked)
		f.wantMode(c, h4, p1, ModeBlocked)
		second := f.cred("ops")
		if err := f.store.Classify(ctx, second, Target{Scope: ScopeLocal}); err != nil {
			t.Fatal(err)
		}
		f.wantMode(second, h1, p1, ModeActive) // same account: shares the recovery
		f.wantMode(c, h1, pw(2), ModeVerifying)

		// H: a new block on the root applies to (H1, ops) again.
		f.addBlockOnRoot(c, h1)
		f.wantMode(c, h1, p1, ModeBlocked)
	})
}

// @ac AC-12
// AC-12: cooldown and allowance, through lineage, with a controlled clock.
func TestCooldownAndAllowance(t *testing.T) {
	t.Run("system-credential-protection/AC-12", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.block(c, h, p1)
		root := f.identity(c, h)
		if _, err := f.store.RequestVerification(ctx, root, p1, f.user); err != nil {
			t.Fatal(err)
		}
		again, err := f.store.RequestVerification(ctx, root, p1, f.user)
		if err != nil {
			t.Fatalf("a repeat request was not a no-op: %v", err)
		}
		if n := f.count(`SELECT count(*) FROM credprotect_verification_requests`); n != 1 {
			t.Fatalf("%d requests after a repeat, want 1 (%v)", n, again)
		}
		v := f.reserve(c, h, p1, KindVerification)
		f.settle(v.ID, OutcomeUnsuccessful)
		f.wantMode(c, h, p1, ModeBlocked)
		f.wantRefused(f.requestErr(root, p1), ErrCooldown)
		f.clock.Advance(Cooldown - time.Second)
		f.wantRefused(f.requestErr(root, p1), ErrCooldown)
		f.clock.Advance(time.Second)
		f.wantRefused(f.requestErr(root, p1), ErrAllowanceUsed)
		lc := f.cred("ops")
		if err := f.store.Classify(ctx, lc, Target{Scope: ScopeLocal}); err != nil {
			t.Fatal(err)
		}
		f.wantRefused(f.requestErr(f.identity(lc, h), p1), ErrAllowanceUsed)
		f.activate(c, h, pw(2)) // a new secret can be verified
	})
}

// @ac AC-13
// AC-13: classification waits for outstanding submissions; nothing copied
// (example E).
func TestClassification(t *testing.T) {
	t.Run("system-credential-protection/AC-13", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h1, h2 := f.host(), f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.activate(c, h1, p1)
		w := f.reserve(c, h1, p1, KindOrdinary)
		f.wantRefused(f.store.Classify(ctx, c, Target{Scope: ScopeLocal}), ErrOutstanding)
		f.settle(w.ID, OutcomeRejected)

		// An outstanding override also refuses it.
		p2 := pw(2)
		f.activate(c, h1, p2)
		o := f.reserve(c, h1, p2, KindOrdinary)
		if err := f.store.Override(ctx, o.ID, f.user, "stuck", true); err != nil {
			t.Fatal(err)
		}
		f.wantRefused(f.store.Classify(ctx, c, Target{Scope: ScopeLocal}), ErrOutstanding)
		f.settle(o.ID, OutcomeNotSubmitted)

		if err := f.store.Classify(ctx, c, Target{Scope: ScopeLocal}); err != nil {
			t.Fatal(err)
		}
		f.wantMode(c, h1, p1, ModeBlocked) // B1 through lineage
		f.wantMode(c, h2, p1, ModeBlocked)
		f.wantMode(c, h1, p2, ModeVerifying) // verified on the root, not copied
		for _, h := range []uuid.UUID{h1, h2} {
			id := f.identity(c, h)
			if n := f.count(`SELECT count(*) FROM credprotect_restrictions WHERE identity_id = $1`, id); n != 0 {
				t.Fatalf("%d restrictions copied to a new identity", n)
			}
			if n := f.count(`SELECT count(*) FROM credprotect_verified_secrets WHERE identity_id = $1`, id); n != 0 {
				t.Fatalf("%d verified secrets copied to a new identity", n)
			}
		}
	})
}

// holdLock holds the username's lock in a separate transaction until the
// returned release is called.
func (f *fixture) holdLock(username string) (release func()) {
	f.t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "credprotect:"+username); err != nil {
		f.t.Fatal(err)
	}
	var once sync.Once
	release = func() { once.Do(func() { _ = tx.Commit(ctx) }) }
	f.t.Cleanup(release) // a failed test must not leave the lock held
	return release
}

// waitForLockWaiter waits until a session in this test database is waiting
// for an advisory lock.
func (f *fixture) waitForLockWaiter() {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if f.count(`SELECT count(*) FROM pg_locks
		             WHERE locktype = 'advisory' AND NOT granted
		               AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatal("no call waited for the username's lock")
}

// @ac AC-05
// AC-05: every write takes the username's lock, and a username edited while
// a reservation waits for it is refused rather than resolved under the old
// name.
func TestEveryWriteTakesTheUsernameLock(t *testing.T) {
	t.Run("system-credential-protection/AC-05", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.activate(c, h, p1)
		root := f.identity(c, h)
		held := f.reserve(c, h, p1, KindOrdinary)
		ops := map[string]func() error{
			"Reserve":             func() error { _, err := f.store.Reserve(ctx, f.req(c, h, pw(2), KindVerification)); return err },
			"Fence":               func() error { return f.store.Fence(ctx, held.ID, Current{Active: true, Secret: p1}) },
			"Resolve":             func() error { _, err := f.store.Resolve(ctx, c, h); return err },
			"Pause":               func() error { _, err := f.store.Pause(ctx, root, "r"); return err },
			"EndPause":            func() error { _, err := f.store.EndPause(ctx, root); return err },
			"RequestVerification": func() error { _, err := f.store.RequestVerification(ctx, root, p1, f.user); return err },
			"Status":              func() error { _, err := f.store.Status(ctx, root, p1); return err },
			"expireOne":           func() error { _, err := f.store.expireOne(ctx, held.ID); return err },
			"Override":            func() error { return f.store.Override(ctx, held.ID, f.user, "r", true) },
			"Classify":            func() error { return f.store.Classify(ctx, f.cred("ops"), Target{Scope: ScopeLocal}) },
			"Settle":              func() error { _, err := f.store.Settle(ctx, held.ID, OutcomeNotSubmitted); return err },
		}
		for _, name := range []string{"Reserve", "Fence", "Resolve", "Pause", "EndPause", "RequestVerification",
			"Status", "expireOne", "Override", "Classify", "Settle"} {
			t.Run(name, func(t *testing.T) {
				release := f.holdLock("ops")
				done := make(chan struct{})
				go func() { _ = ops[name](); close(done) }()
				f.waitForLockWaiter()
				select {
				case <-done:
					release()
					t.Fatalf("%s finished while the username's lock was held", name)
				default:
				}
				release()
				<-done
			})
		}

		t.Run("a username edited under the lock", func(t *testing.T) {
			g := newFixture(t)
			gh := g.host()
			gc := g.cred("ops")
			release := g.holdLock("ops")
			errc := make(chan error, 1)
			go func() { _, err := g.store.Reserve(ctx, g.req(gc, gh, pw(1), KindVerification)); errc <- err }()
			g.waitForLockWaiter()
			if _, err := g.pool.Exec(ctx, `UPDATE credentials SET username = 'dev' WHERE id = $1`, gc); err != nil {
				t.Fatal(err)
			}
			release()
			g.wantRefused(<-errc, ErrInvalid)
			if n := g.count(`SELECT count(*) FROM credprotect_submissions`); n != 0 {
				t.Fatal("a reservation was made under the old username")
			}
		})
	})
}

// @ac AC-06
// AC-06: the slot check stands on its own, before the deadline.
func TestFenceRefusesAReleasedSlotBeforeItsDeadline(t *testing.T) {
	t.Run("system-credential-protection/AC-06", func(t *testing.T) {
		f := newFixture(t)
		h := f.host()
		c := f.cred("ops")
		f.activate(c, h, pw(1))
		sub := f.reserve(c, h, pw(1), KindOrdinary)
		f.settle(sub.ID, OutcomeVerified)
		f.wantRefused(f.store.Fence(context.Background(), sub.ID, Current{Active: true, Secret: pw(1)}), ErrFenceRefused)
	})
}

// @ac AC-04
// AC-04: a request needs an unlifted block.
func TestRequestNeedsABlock(t *testing.T) {
	t.Run("system-credential-protection/AC-04", func(t *testing.T) {
		f := newFixture(t)
		h := f.host()
		c := f.cred("ops")
		f.activate(c, h, pw(1))
		f.wantRefused(f.requestErr(f.identity(c, h), pw(1)), ErrNotVerifying)
		f.wantRefused(f.requestErr(f.identity(c, h), pw(2)), ErrNotVerifying)
	})
}

// @ac AC-07
// AC-07: expiry leaves a submission settled since its scan alone.
func TestExpiryLeavesASettledSubmissionAlone(t *testing.T) {
	t.Run("system-credential-protection/AC-07", func(t *testing.T) {
		f := newFixture(t)
		h := f.host()
		c := f.cred("ops")
		f.activate(c, h, pw(1))
		sub := f.reserve(c, h, pw(1), KindOrdinary)
		f.clock.Advance(6 * time.Minute)
		f.settle(sub.ID, OutcomeRejected)
		expired, err := f.store.expireOne(context.Background(), sub.ID)
		if err != nil || expired {
			t.Fatalf("expireOne on a settled submission: %v, %v", expired, err)
		}
		if n := f.count(`SELECT count(*) FROM credprotect_restrictions WHERE submission_id = $1`, sub.ID); n != 1 {
			t.Fatalf("%d restrictions, want the one block from the settlement", n)
		}
	})
}

// @ac AC-12
// AC-12: a cooldown and a used allowance reach a descendant's pending
// verification through lineage.
func TestInheritedCooldownRefusesAPendingVerification(t *testing.T) {
	t.Run("system-credential-protection/AC-12", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		rootCred, localCred := f.cred("ops"), f.cred("ops")
		if err := f.store.Classify(ctx, localCred, Target{Scope: ScopeLocal}); err != nil {
			t.Fatal(err)
		}
		p1 := pw(1)
		f.block(rootCred, f.host(), p1)
		for _, id := range []uuid.UUID{f.identity(rootCred, h), f.identity(localCred, h)} {
			if _, err := f.store.RequestVerification(ctx, id, p1, f.user); err != nil {
				t.Fatal(err)
			}
		}
		v := f.reserve(rootCred, h, p1, KindVerification)
		f.settle(v.ID, OutcomeUnsuccessful)
		f.wantMode(localCred, h, p1, ModeVerifying) // its own request is still pending
		_, err := f.store.Reserve(ctx, f.req(localCred, h, p1, KindVerification))
		f.wantRefused(err, ErrCooldown)
		f.clock.Advance(Cooldown)
		_, err = f.store.Reserve(ctx, f.req(localCred, h, p1, KindVerification))
		f.wantRefused(err, ErrAllowanceUsed)
	})
}

// @ac AC-07
// AC-07: the owner's unknown after expiry's unknown is late, not a
// duplicate, and releases the slot.
func TestOwnerUnknownAfterExpiryIsLate(t *testing.T) {
	t.Run("system-credential-protection/AC-07", func(t *testing.T) {
		f := newFixture(t)
		h := f.host()
		c := f.cred("ops")
		f.activate(c, h, pw(1))
		sub := f.reserve(c, h, pw(1), KindOrdinary)
		f.clock.Advance(6 * time.Minute)
		if _, err := f.store.Expire(context.Background()); err != nil {
			t.Fatal(err)
		}
		res := f.settle(sub.ID, OutcomeUnknown)
		if res.Duplicate || !res.Late || !res.Released {
			t.Fatalf("owner's unknown after expiry: %+v", res)
		}
	})
}

// @ac AC-02
// AC-02: an existing local identity deepens when a credential classified
// below a directory reaches it.
func TestLocalIdentityDeepensBelowADirectory(t *testing.T) {
	t.Run("system-credential-protection/AC-02", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		viaRoot := f.cred("ops")
		if err := f.store.Classify(ctx, viaRoot, Target{Scope: ScopeLocal}); err != nil {
			t.Fatal(err)
		}
		id := f.identity(viaRoot, h)
		if f.depth(id) != 2 {
			t.Fatalf("depth %d, want 2", f.depth(id))
		}
		dir, err := f.store.CreateDirectory(ctx, "corp", "ops")
		if err != nil {
			t.Fatal(err)
		}
		viaDir := f.cred("ops")
		if err := f.store.Classify(ctx, viaDir, Target{Scope: ScopeDirectory, Directory: dir}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Classify(ctx, viaDir, Target{Scope: ScopeLocal}); err != nil {
			t.Fatal(err)
		}
		if got := f.identity(viaDir, h); got != id {
			t.Fatal("one account on one host resolved to two local identities")
		}
		if f.depth(id) != 3 {
			t.Fatalf("depth %d after gaining a directory parent, want 3", f.depth(id))
		}
		if !f.hasAncestor(id, dir) {
			t.Fatal("the directory is not an ancestor")
		}
	})
}

// @ac AC-01
// AC-01: a local credential resolves only for a host.
func TestLocalNeedsAHost(t *testing.T) {
	t.Run("system-credential-protection/AC-01", func(t *testing.T) {
		f := newFixture(t)
		c := f.cred("ops")
		if err := f.store.Classify(context.Background(), c, Target{Scope: ScopeLocal}); err != nil {
			t.Fatal(err)
		}
		_, err := f.store.Resolve(context.Background(), c, uuid.Nil)
		f.wantRefused(err, ErrInvalid)
	})
}

// @ac AC-05
// AC-05: a reservation without its parts reserves nothing.
func TestReservationNeedsItsParts(t *testing.T) {
	t.Run("system-credential-protection/AC-05", func(t *testing.T) {
		f := newFixture(t)
		h := f.host()
		c := f.cred("ops")
		ctx := context.Background()
		for name, mut := range map[string]func(*Request){
			"no TTL":         func(r *Request) { r.TTL = 0 },
			"no stage":       func(r *Request) { r.Stage = "" },
			"no machine":     func(r *Request) { r.Owner.Machine = "" },
			"no pid":         func(r *Request) { r.Owner.PID = 0 },
			"unknown kind":   func(r *Request) { r.Kind = "bulk" },
			"no identifier":  func(r *Request) { r.Secret.Aliases = nil },
			"unknown secret": func(r *Request) { r.Secret.Kind = "token" },
		} {
			r := f.req(c, h, pw(1), KindVerification)
			mut(&r)
			if _, err := f.store.Reserve(ctx, r); err == nil {
				t.Fatalf("%s: reserved", name)
			}
		}
		if _, err := f.store.Settle(ctx, uuid.Must(uuid.NewV7()), "maybe"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("an unknown outcome: %v", err)
		}
		if n := f.count(`SELECT count(*) FROM credprotect_submissions`); n != 0 {
			t.Fatalf("%d submissions reserved", n)
		}
	})
}

// @ac AC-04
// AC-04: nothing is reserved, of either kind, and nothing passes the fence,
// while a pause applies.
func TestPausedRefusesEverything(t *testing.T) {
	t.Run("system-credential-protection/AC-04", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.activate(c, h, p1)
		held := f.reserve(c, h, p1, KindOrdinary)
		root := f.identity(c, h)
		if _, err := f.store.Pause(ctx, root, "change freeze"); err != nil {
			t.Fatal(err)
		}
		f.wantRefused(f.store.Fence(ctx, held.ID, Current{Active: true, Secret: p1}), ErrPaused)
		f.settle(held.ID, OutcomeNotSubmitted)
		for _, s := range []Secret{p1, pw(2)} {
			for _, k := range []Kind{KindOrdinary, KindVerification} {
				_, err := f.store.Reserve(ctx, f.req(c, h, s, k))
				f.wantRefused(err, ErrPaused)
			}
		}
	})
}

// @ac AC-06
// AC-06: the fence accepts the current secret by any of its aliases, as
// after a fingerprint-key rotation.
func TestFenceMatchesAnyAlias(t *testing.T) {
	t.Run("system-credential-protection/AC-06", func(t *testing.T) {
		f := newFixture(t)
		h := f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.activate(c, h, p1)
		sub := f.reserve(c, h, p1, KindOrdinary)
		var k2 Alias
		k2.KeyID = "k2"
		k2.ID[0] = 9
		rotated := Secret{Kind: SecretPassword, Aliases: []Alias{k2, p1.Aliases[0]}}
		if err := f.store.Fence(context.Background(), sub.ID, Current{Active: true, Secret: rotated}); err != nil {
			t.Fatalf("the fence refused the current secret under a second alias: %v", err)
		}
		other := Secret{Kind: SecretKey, Aliases: []Alias{p1.Aliases[0]}}
		f.wantRefused(f.store.Fence(context.Background(), sub.ID, Current{Active: true, Secret: other}), ErrFenceRefused)
	})
}

// rotated is P1 identified under a new key first and its old key second,
// as during a fingerprint-key rotation.
func rotated() Secret {
	s := pw(1)
	var k2 Alias
	k2.KeyID = "k2"
	k2.ID[0] = 0xA2
	return Secret{Kind: SecretPassword, Aliases: []Alias{k2, s.Aliases[0]}}
}

// @ac AC-03
// AC-03: a submission keeps every alias it was reserved with, so the fence,
// expiry and settlement see restrictions and verification recorded under
// any of them (review of #950, finding 1).
func TestSubmissionsKeepEveryAlias(t *testing.T) {
	t.Run("system-credential-protection/AC-03", func(t *testing.T) {
		t.Run("verified under the old alias", func(t *testing.T) {
			f := newFixture(t)
			h := f.host()
			c := f.cred("ops")
			f.activate(c, h, pw(1))
			sub := f.reserve(c, h, rotated(), KindOrdinary)
			if n := f.count(`SELECT cardinality(alias_ids) FROM credprotect_submissions WHERE id = $1`, sub.ID); n != 2 {
				t.Fatalf("%d aliases stored, want 2", n)
			}
			if err := f.store.Fence(context.Background(), sub.ID, Current{Active: true, Secret: rotated()}); err != nil {
				t.Fatalf("the fence refused a verified secret reserved under a new alias: %v", err)
			}
		})
		t.Run("a block under the old alias reaches a rotated verification", func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			h := f.host()
			c := f.cred("ops")
			if err := f.store.Classify(ctx, c, Target{Scope: ScopeLocal}); err != nil {
				t.Fatal(err)
			}
			v := f.reserve(c, h, rotated(), KindVerification)
			f.block(f.cred("ops"), f.host(), pw(1)) // on the root, under the old alias
			err := f.store.Fence(ctx, v.ID, Current{Active: true, Secret: rotated()})
			f.wantRefused(err, ErrBlocked)
			if res := f.settle(v.ID, OutcomeVerified); res.Recovery != uuid.Nil {
				t.Fatal("recovered despite a block under the old alias")
			}
			f.wantMode(c, h, rotated(), ModeBlocked)
		})
	})
}

// @ac AC-01
// AC-01: a username edited after classification resolves under the new
// username's root until the credential is classified again, and a
// submission reserved before the edit fails the fence (finding 2).
func TestUsernameEditAfterClassification(t *testing.T) {
	t.Run("system-credential-protection/AC-01", func(t *testing.T) {
		for _, scope := range []Scope{ScopeLocal, ScopeDirectory} {
			t.Run(string(scope), func(t *testing.T) {
				f := newFixture(t)
				ctx := context.Background()
				h := f.host()
				c := f.cred("old-user")
				to := Target{Scope: scope}
				if scope == ScopeDirectory {
					d, err := f.store.CreateDirectory(ctx, "corp", "old-user")
					if err != nil {
						t.Fatal(err)
					}
					to.Directory = d
				}
				if err := f.store.Classify(ctx, c, to); err != nil {
					t.Fatal(err)
				}
				f.block(f.cred("new-user"), f.host(), pw(1))
				if _, err := f.pool.Exec(ctx, `UPDATE credentials SET username = 'new-user' WHERE id = $1`, c); err != nil {
					t.Fatal(err)
				}
				newRoot := f.identity(f.cred("new-user"), h)
				if got := f.identity(c, h); got != newRoot {
					t.Fatalf("a stale classification resolved to %v, not the new root %v", got, newRoot)
				}
				f.wantMode(c, h, pw(1), ModeBlocked)
				// It can be classified again, below the new root, and keeps the block.
				if err := f.store.Classify(ctx, c, Target{Scope: ScopeLocal}); err != nil {
					t.Fatalf("reclassifying a stale classification: %v", err)
				}
				if !f.hasAncestor(f.identity(c, h), newRoot) {
					t.Fatal("the new local identity is not below the new root")
				}
				f.wantMode(c, h, pw(1), ModeBlocked)
			})
		}
		t.Run("a submission reserved before the edit", func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			h := f.host()
			c := f.cred("ops")
			f.activate(c, h, pw(1))
			sub := f.reserve(c, h, pw(1), KindOrdinary)
			if _, err := f.pool.Exec(ctx, `UPDATE credentials SET username = 'dev' WHERE id = $1`, c); err != nil {
				t.Fatal(err)
			}
			f.wantRefused(f.store.Fence(ctx, sub.ID, Current{Active: true, Secret: pw(1)}), ErrFenceRefused)
		})
	})
}

// @ac AC-10
// AC-10: an overridden verification's success is evidence only, even before
// its deadline; the request stands, and a later verification can still
// recover (finding 3).
func TestOverriddenVerificationIsEvidenceOnly(t *testing.T) {
	t.Run("system-credential-protection/AC-10", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		f.block(c, h, pw(1))
		if _, err := f.store.RequestVerification(ctx, f.identity(c, h), pw(1), f.user); err != nil {
			t.Fatal(err)
		}
		v := f.reserve(c, h, pw(1), KindVerification)
		if err := f.store.Override(ctx, v.ID, f.user, "owner stalled", true); err != nil {
			t.Fatal(err)
		}
		res := f.settle(v.ID, OutcomeVerified)
		if res.Late || res.Recovery != uuid.Nil {
			t.Fatalf("an overridden verification recovered before its deadline: %+v", res)
		}
		f.wantMode(c, h, pw(1), ModeVerifying)
		again := f.reserve(c, h, pw(1), KindVerification)
		if res := f.settle(again.ID, OutcomeVerified); res.Recovery == uuid.Nil {
			t.Fatal("a later, unoverridden verification did not recover")
		}
		f.wantMode(c, h, pw(1), ModeActive)
	})
}

// failingProcs cannot determine whether a process exists.
type failingProcs struct{}

func (failingProcs) Machine() string { return "m1" }
func (failingProcs) Alive(int, string) (bool, error) {
	return false, errors.New("cannot read the process table")
}

// @ac AC-08
// AC-08: an incomplete or indeterminate owner identity never releases a slot
// (finding 4).
func TestIndeterminateOwnerNeverReleasesASlot(t *testing.T) {
	t.Run("system-credential-protection/AC-08", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		r := f.req(c, h, pw(1), KindVerification)
		r.Owner.Start = ""
		_, err := f.store.Reserve(ctx, r)
		f.wantRefused(err, ErrInvalid)
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO credprotect_submissions (id, identity_id, kind, stage, secret_kind,
			       alias_key_ids, alias_ids, owner_machine, owner_pid, owner_start, reserved_at, deadline, snapshot, slot_held)
			VALUES ($1, $2, 'ordinary', 'ssh', 'password', '{k1}', '{"\\x00"}', 'm1', 1, '', now(), now(), '{}', false)`,
			uuid.Must(uuid.NewV7()), f.identity(c, h)); err == nil ||
			!strings.Contains(err.Error(), "credprotect_submissions_owner_whole") {
			t.Fatalf("an owner with no start time: %v, want the owner constraint", err)
		}
		for _, bad := range []struct {
			pid   int
			start string
		}{{0, "1"}, {-1, "1"}, {1, ""}} {
			if _, err := (LocalProcesses{}).Alive(bad.pid, bad.start); err == nil {
				t.Fatalf("Alive(%d, %q) gave an answer for an incomplete identity", bad.pid, bad.start)
			}
		}
		sub := f.reserve(c, h, pw(1), KindVerification)
		s := New(f.pool, WithClock(f.clock), WithProcesses(failingProcs{}))
		_, err = s.ReleaseIfTerminated(ctx, sub.ID)
		f.wantRefused(err, ErrNotTerminated)
		if !f.slotHeld(sub.ID) {
			t.Fatal("an indeterminate process check released the slot")
		}
	})
}

// @ac AC-06
// AC-06: the fence refuses once the submission's credential is deleted.
func TestFenceRefusesADeletedCredential(t *testing.T) {
	t.Run("system-credential-protection/AC-06", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		f.activate(c, h, pw(1))
		sub := f.reserve(c, h, pw(1), KindOrdinary)
		if _, err := f.pool.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, c); err != nil {
			t.Fatal(err)
		}
		f.wantRefused(f.store.Fence(ctx, sub.ID, Current{Active: true, Secret: pw(1)}), ErrFenceRefused)
		if !f.slotHeld(sub.ID) {
			t.Fatal("deleting the credential released the slot")
		}
	})
}

// @ac AC-03
// AC-03: a restriction records every alias its writer presented, so it
// reaches an unresolved submission that shares any one of them, in either
// direction of a rotation (review round 2, finding 1).
func TestRestrictionsReachSubmissionsSharingAnyAlias(t *testing.T) {
	t.Run("system-credential-protection/AC-03", func(t *testing.T) {
		for name, c := range map[string]struct{ reserved, blockedBy Secret }{
			"reserved under old, blocked under new and old": {pw(1), rotated()},
			"reserved under new and old, blocked under old": {rotated(), pw(1)},
		} {
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				ctx := context.Background()
				h := f.host()
				local := f.cred("ops")
				if err := f.store.Classify(ctx, local, Target{Scope: ScopeLocal}); err != nil {
					t.Fatal(err)
				}
				v := f.reserve(local, h, c.reserved, KindVerification)
				f.block(f.cred("ops"), f.host(), c.blockedBy) // on the root
				for _, cur := range []Secret{c.reserved, rotated()} {
					f.wantRefused(f.store.Fence(ctx, v.ID, Current{Active: true, Secret: cur}), ErrBlocked)
				}
				if res := f.settle(v.ID, OutcomeVerified); res.Recovery != uuid.Nil {
					t.Fatal("recovered past a block recorded under a shared alias")
				}
			})
		}
	})
}

// @ac AC-03
// AC-03: a secret verified under [new, old] stays ACTIVE for a caller that
// presents old alone, and for one that presents new alone.
func TestVerifiedSecretsRecordEveryAlias(t *testing.T) {
	t.Run("system-credential-protection/AC-03", func(t *testing.T) {
		f := newFixture(t)
		h := f.host()
		c := f.cred("ops")
		f.activate(c, h, rotated())
		f.wantMode(c, h, pw(1), ModeActive)
		newOnly := Secret{Kind: SecretPassword, Aliases: rotated().Aliases[:1]}
		f.wantMode(c, h, newOnly, ModeActive)
		f.reserve(c, h, pw(1), KindOrdinary)
	})
}
