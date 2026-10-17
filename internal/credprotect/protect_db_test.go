// @spec system-credential-protection
//
// Protection state and reservations against PostgreSQL, with a controlled
// clock and process table. Examples D to H are those of contract r3,
// section 18 (features/OW-122); account scope cases are in
// account_db_test.go.

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

// rotated is P1 identified under a new key first and its old key second,
// as during a fingerprint-key rotation.
func rotated() Secret {
	s := pw(1)
	var k2 Alias
	k2.KeyID = fixtureKeyring.previous
	k2.ID[0] = 0xA2
	return Secret{Kind: SecretPassword, Keyring: s.Keyring, Aliases: []Alias{k2, s.Aliases[0]}}
}

// @ac AC-01
// AC-01: resolution by class.
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
		l := f.localCred("ops")
		if f.identity(l, h1) != root || f.status(l, h1, pw(1)).Class != ClassUnconfirmed {
			t.Fatal("a local credential on a host that is not confirmed was not unconfirmed")
		}
		f.confirm(h1, "ops")
		hr := f.identity(l, h1)
		if hr == root || f.status(l, h1, pw(1)).Class != ClassConfirmedLocal {
			t.Fatal("a local credential on a confirmed host did not resolve to its host record")
		}
		if f.identity(l, h2) != root {
			t.Fatal("a confirmation reached another host")
		}
		d := f.directory("corp", "ops", AdmissionUsable)
		dc := f.dirCred("ops", d)
		if f.identity(dc, h2) != d || f.status(dc, h2, pw(1)).Class != ClassDirectory {
			t.Fatal("a directory credential did not resolve to its directory identity")
		}
		if _, err := f.pool.Exec(ctx, `UPDATE credentials SET username = 'dev' WHERE id = $1`, dc); err != nil {
			t.Fatal(err)
		}
		if f.identity(dc, h2) != f.identity(f.cred("dev"), h2) {
			t.Fatal("a stale directory classification did not resolve to the new root")
		}
		_, err := f.store.Resolve(ctx, l, uuid.Nil)
		f.wantRefused(err, ErrInvalid)
	})
}

// @ac AC-02
// AC-02: classification in every direction; refusals change nothing.
func TestClassification(t *testing.T) {
	t.Run("system-credential-protection/AC-02", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		d := f.directory("corp", "ops", AdmissionUsable)
		other := f.directory("svc-corp", "svc", AdmissionUsable)
		c := f.cred("ops")
		for _, to := range []Target{{Scope: ScopeLocal}, {Scope: ScopeDirectory, Directory: d}, {Scope: ScopeLocal},
			{Scope: ScopeUnconfirmed}, {Scope: ScopeDirectory, Directory: d}, {Scope: ScopeUnconfirmed}} {
			f.classify(c, to)
		}
		if f.identity(c, h) != f.identity(f.cred("ops"), h) {
			t.Fatal("classified back to unconfirmed, it does not resolve to the root")
		}
		before := f.count(`SELECT count(*) FROM credprotect_credential_classes`)
		f.wantRefused(f.store.Classify(ctx, c, Target{Scope: ScopeDirectory, Directory: other}), ErrClassification)
		f.wantRefused(f.store.Classify(ctx, c, Target{Scope: "global"}), ErrClassification)
		f.wantRefused(f.store.Classify(ctx, c, Target{Scope: ScopeDirectory, Directory: uuid.Must(uuid.NewV7())}),
			ErrClassification)
		cand := f.directory("corp-2", "ops", AdmissionCandidate)
		if err := f.store.ResolveSame(ctx, cand, d, f.user, "same forest"); err != nil {
			t.Fatal(err)
		}
		f.wantRefused(f.store.Classify(ctx, c, Target{Scope: ScopeDirectory, Directory: cand}), ErrClassification)
		if after := f.count(`SELECT count(*) FROM credprotect_credential_classes`); after != before {
			t.Fatal("a refused classification changed a classification")
		}
		r := f.req(c, uuid.Nil, pw(1), KindVerification)
		_, err := f.store.Reserve(ctx, r)
		f.wantRefused(err, ErrInvalid)
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

		f.wantMode(c, h, rotated(), ModeBlocked)
		f.wantMode(c, h, pw(3), ModeVerifying)

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

// @ac AC-03
// AC-03: every row keeps every alias, in both directions of a rotation.
func TestAliasesSurviveEveryRow(t *testing.T) {
	t.Run("system-credential-protection/AC-03", func(t *testing.T) {
		t.Run("a submission stores every alias", func(t *testing.T) {
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
		for name, c := range map[string]struct{ reserved, blockedBy Secret }{
			"reserved under old, blocked under new and old": {pw(1), rotated()},
			"reserved under new and old, blocked under old": {rotated(), pw(1)},
		} {
			t.Run(name, func(t *testing.T) {
				// A confirmed-local verification holds its slot; an unconfirmed
				// attempt on another host does not conflict with it and blocks
				// the root, which is in its lineage, under the other alias set.
				f := newFixture(t)
				ctx := context.Background()
				h := f.host()
				lc := f.localCred("ops")
				f.confirm(h, "ops")
				uc := f.cred("ops")
				f.activate(uc, f.host(), c.blockedBy)
				v := f.reserve(lc, h, c.reserved, KindVerification)
				f.block(uc, f.host(), c.blockedBy)
				for _, cur := range []Secret{c.reserved, rotated()} {
					f.wantRefused(f.store.Fence(ctx, v.ID, Current{Active: true, Secret: cur}), ErrBlocked)
				}
				if res := f.settle(v.ID, OutcomeVerified); res.Recovery != uuid.Nil {
					t.Fatal("recovered past a block recorded under a shared alias")
				}
			})
		}
		t.Run("a verified secret records every alias", func(t *testing.T) {
			f := newFixture(t)
			h := f.host()
			c := f.cred("ops")
			f.activate(c, h, rotated())
			f.wantMode(c, h, pw(1), ModeActive)
			f.wantMode(c, h, Secret{Kind: SecretPassword, Keyring: fixtureKeyring.keyring.Snapshot(), Aliases: rotated().Aliases[:1]}, ModeActive)
			f.reserve(c, h, pw(1), KindOrdinary)
		})
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
		if err := f.request(c, h, p1); err != nil {
			t.Fatal(err)
		}
		f.wantMode(c, h, p1, ModeVerifying)

		// A pause on the root reaches a confirmed-local account; ending
		// "it" on the host record ends nothing.
		lc := f.localCred("ops")
		f.confirm(h, "ops")
		root, hr := f.identity(c, h), f.identity(lc, h)
		if _, err := f.store.Pause(ctx, root, "maintenance"); err != nil {
			t.Fatal(err)
		}
		f.wantMode(lc, h, pw(5), ModePaused)
		if n, err := f.store.EndPause(ctx, hr); err != nil || n != 0 {
			t.Fatalf("EndPause on the host record ended %d pauses (%v)", n, err)
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
		f.wantRefused(f.request(c, h, p6), ErrCooldown)
		f.clock.Advance(Cooldown)
		f.wantRefused(f.request(c, h, p6), ErrAllowanceUsed)
	})
}

// @ac AC-04
// AC-04: a request needs a block, and a pause stops everything.
func TestRequestNeedsABlockAndPauseStopsEverything(t *testing.T) {
	t.Run("system-credential-protection/AC-04", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.activate(c, h, p1)
		f.wantRefused(f.request(c, h, p1), ErrNotVerifying)
		f.wantRefused(f.request(c, h, pw(2)), ErrNotVerifying)
		held := f.reserve(c, h, p1, KindOrdinary)
		if _, err := f.store.Pause(ctx, f.identity(c, h), "change freeze"); err != nil {
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
		if err := f.request(c, h, p1); err != nil {
			t.Fatal(err)
		}
		v := f.reserve(c, h, p1, KindVerification)
		if len(v.Snapshot) != 1 || v.Snapshot[0] != b1 {
			t.Fatalf("snapshot = %v, want [%v]", v.Snapshot, b1)
		}
		f.settle(v.ID, OutcomeVerified)

		t.Run("eight workers race for one scope", func(t *testing.T) {
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
			if err := g.request(gc, gh, p1); err != nil {
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
// a reservation waits for it is refused.
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
		cand := uuid.Nil
		ops := map[string]func() error{
			"Reserve":             func() error { _, err := f.store.Reserve(ctx, f.req(c, h, pw(2), KindVerification)); return err },
			"Fence":               func() error { return f.store.Fence(ctx, held.ID, Current{Active: true, Secret: p1}) },
			"Resolve":             func() error { _, err := f.store.Resolve(ctx, c, h); return err },
			"Status":              func() error { _, err := f.store.Status(ctx, c, h, p1); return err },
			"Pause":               func() error { _, err := f.store.Pause(ctx, root, "r"); return err },
			"EndPause":            func() error { _, err := f.store.EndPause(ctx, root); return err },
			"RequestVerification": func() error { _, err := f.store.RequestVerification(ctx, c, h, p1, f.user); return err },
			"ConfirmLocal":        func() error { return f.store.ConfirmLocal(ctx, h, "ops", f.user, "b") },
			"WithdrawLocal":       func() error { return f.store.WithdrawLocal(ctx, h, "ops") },
			"CreateDirectory":     func() error { var err error; cand, _, err = f.store.CreateDirectory(ctx, "d", "ops"); return err },
			"AssertDistinct":      func() error { return f.store.AssertDistinct(ctx, cand, nil, f.user, "b") },
			"expireOne":           func() error { _, err := f.store.expireOne(ctx, held.ID); return err },
			"Override":            func() error { return f.store.Override(ctx, held.ID, f.user, "r", true) },
			"Classify":            func() error { return f.store.Classify(ctx, c, Target{Scope: ScopeLocal}) },
			"Settle":              func() error { _, err := f.store.Settle(ctx, held.ID, OutcomeNotSubmitted); return err },
		}
		for _, name := range []string{"Reserve", "Fence", "Resolve", "Status", "Pause", "EndPause",
			"RequestVerification", "ConfirmLocal", "WithdrawLocal", "CreateDirectory", "AssertDistinct", "expireOne",
			"Override", "Classify", "Settle"} {
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
			"no start time":  func(r *Request) { r.Owner.Start = "" },
			"no host":        func(r *Request) { r.HostID = uuid.Nil },
			"unknown kind":   func(r *Request) { r.Kind = "bulk" },
			"no identifier":  func(r *Request) { r.Secret.Aliases = nil },
			"unknown secret": func(r *Request) { r.Secret.Kind = "token" },
		} {
			r := f.req(c, h, pw(1), KindVerification)
			mut(&r)
			if _, err := f.store.Reserve(ctx, r); !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s: %v, want ErrInvalid from the request check", name, err)
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
		var k2 Alias
		k2.KeyID = fixtureKeyring.previous
		k2.ID[0] = 9
		if err := f.store.Fence(ctx, sub.ID, Current{Active: true, Secret: Secret{Kind: SecretPassword, Keyring: fixtureKeyring.keyring.Snapshot(),
			Aliases: []Alias{k2, p1.Aliases[0]}}}); err != nil {
			t.Fatalf("the fence refused the secret under a second alias: %v", err)
		}
		f.wantRefused(f.store.Fence(ctx, sub.ID, Current{Active: true, Secret: Secret{Kind: SecretKey,
			Aliases: p1.Aliases}}), ErrFenceRefused)
		f.wantRefused(f.store.Fence(ctx, sub.ID, Current{Active: false, Secret: p1}), ErrFenceRefused)
		f.wantRefused(f.store.Fence(ctx, sub.ID, Current{Active: true, Secret: pw(2)}), ErrFenceRefused)
		f.clock.Advance(5 * time.Minute)
		f.wantRefused(f.store.Fence(ctx, sub.ID, cur), ErrFenceRefused)
		f.settle(sub.ID, OutcomeVerified)

		t.Run("a released slot, before its deadline", func(t *testing.T) {
			s := f.reserve(c, h, p1, KindOrdinary)
			f.settle(s.ID, OutcomeVerified)
			f.wantRefused(f.store.Fence(ctx, s.ID, cur), ErrFenceRefused)
		})
		t.Run("a username edit and a deletion", func(t *testing.T) {
			g := newFixture(t)
			gh := g.host()
			for _, edit := range []string{`UPDATE credentials SET username = 'dev' WHERE id = $1`,
				`DELETE FROM credentials WHERE id = $1`} {
				gc := g.cred("ops")
				if g.mode(gc, gh, p1) != ModeActive {
					g.activate(gc, gh, p1)
				}
				s := g.reserve(gc, gh, p1, KindOrdinary)
				if _, err := g.pool.Exec(ctx, edit, gc); err != nil {
					t.Fatal(err)
				}
				g.wantRefused(g.store.Fence(ctx, s.ID, cur), ErrFenceRefused)
				if !g.slotHeld(s.ID) {
					t.Fatal("the edit released the slot")
				}
				g.settle(s.ID, OutcomeNotSubmitted)
			}
		})
		t.Run("a block that appears after reserve", func(t *testing.T) {
			// A confirmed-local attempt holds its slot while an unconfirmed
			// attempt on another host blocks the root, its lineage.
			g := newFixture(t)
			gh := g.host()
			lc := g.localCred("ops")
			g.confirm(gh, "ops")
			g.activate(lc, gh, p1)
			uc := g.cred("ops")
			g.activate(uc, g.host(), p1)
			held := g.reserve(lc, gh, p1, KindOrdinary)
			if err := g.store.Fence(ctx, held.ID, cur); err != nil {
				t.Fatalf("fence before the block: %v", err)
			}
			g.block(uc, g.host(), p1)
			g.wantRefused(g.store.Fence(ctx, held.ID, cur), ErrBlocked)
		})
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

		f.activate(c, h, p2)
		exp := f.reserve(c, h, p2, KindOrdinary)
		f.clock.Advance(6 * time.Minute)
		if n, err := f.store.Expire(ctx); err != nil || n != 1 {
			t.Fatalf("Expire = %d, %v", n, err)
		}
		if res := f.settle(exp.ID, OutcomeVerified); !res.Late || !res.Released {
			t.Fatal("the owner's outcome after expiry was not late, or kept the slot")
		}
		if res := f.settle(exp.ID, OutcomeVerified); !res.Duplicate {
			t.Fatal("a repeated late outcome was not a no-op")
		}
		_, err = f.store.Settle(ctx, exp.ID, OutcomeRejected)
		f.wantRefused(err, ErrOutcomeConflict)

		f.activate(c, h, p3)
		slow := f.reserve(c, h, p3, KindOrdinary)
		f.clock.Advance(5 * time.Minute)
		if res := f.settle(slow.ID, OutcomeVerified); !res.Late {
			t.Fatal("an outcome after the deadline was not late")
		}

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

		t.Run("the owner's unknown after expiry is late", func(t *testing.T) {
			p5 := pw(5)
			f.activate(c, h, p5)
			s := f.reserve(c, h, p5, KindOrdinary)
			f.clock.Advance(6 * time.Minute)
			if _, err := f.store.Expire(ctx); err != nil {
				t.Fatal(err)
			}
			if res := f.settle(s.ID, OutcomeUnknown); res.Duplicate || !res.Late || !res.Released {
				t.Fatalf("owner's unknown after expiry: %+v", res)
			}
		})
		t.Run("expiry leaves a settled submission alone", func(t *testing.T) {
			p6 := pw(6)
			f.activate(c, h, p6)
			s := f.reserve(c, h, p6, KindOrdinary)
			f.clock.Advance(6 * time.Minute)
			f.settle(s.ID, OutcomeRejected)
			expired, err := f.store.expireOne(ctx, s.ID)
			if err != nil || expired {
				t.Fatalf("expireOne on a settled submission: %v, %v", expired, err)
			}
			if n := f.count(`SELECT count(*) FROM credprotect_restrictions WHERE submission_id = $1`, s.ID); n != 1 {
				t.Fatalf("%d restrictions, want the one block from the settlement", n)
			}
		})
	})
}

func (f *fixture) slotHeld(id uuid.UUID) bool {
	return f.count(`SELECT CASE WHEN slot_held THEN 1 ELSE 0 END FROM credprotect_submissions WHERE id = $1`, id) == 1
}

func (f *fixture) setOwnerMachine(id uuid.UUID, m string) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE credprotect_submissions SET owner_machine = $2 WHERE id = $1`, id, m); err != nil {
		f.t.Fatal(err)
	}
}

// failingProcs cannot determine whether a process exists.
type failingProcs struct{}

func (failingProcs) Machine() string { return "m1" }
func (failingProcs) Alive(int, string) (bool, error) {
	return false, errors.New("cannot read the process table")
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
		f.procs.kill(4242)
		f.setOwnerMachine(w1.ID, "m2")
		_, err := f.store.ReleaseIfTerminated(ctx, w1.ID)
		f.wantRefused(err, ErrNotTerminated)
		f.wantRefused(f.store.Override(ctx, w1.ID, f.user, "", true), ErrOverride)
		f.wantRefused(f.store.Override(ctx, w1.ID, f.user, "host unreachable", false), ErrOverride)
		if err := f.store.Override(ctx, w1.ID, f.user, "host unreachable", true); err != nil {
			t.Fatal(err)
		}
		if st := f.status(c, h, p1); st.K+st.O != 2 {
			t.Fatalf("bound K + o = %d, want 2", st.K+st.O)
		}
		if err := f.request(c, h, p1); err != nil {
			t.Fatal(err)
		}
		v := f.reserve(c, h, p1, KindVerification)
		if res := f.settle(v.ID, OutcomeVerified); res.Recovery == uuid.Nil {
			t.Fatal("the verification did not recover")
		}
		f.wantMode(c, h, p1, ModeActive)
		if res := f.settle(w1.ID, OutcomeVerified); !res.Late || !res.Released {
			t.Fatalf("W1's late report: %+v", res)
		}
		if st := f.status(c, h, p1); st.O != 0 {
			t.Fatalf("o = %d after W1 reported, want 0", st.O)
		}

		f.procs.alive[4242] = "100"
		p2 := pw(2)
		f.activate(c, h, p2)
		s2 := f.reserve(c, h, p2, KindOrdinary)
		_, err = f.store.ReleaseIfTerminated(ctx, s2.ID)
		f.wantRefused(err, ErrNotTerminated)
		indeterminate := New(f.pool, WithClock(f.clock), WithProcesses(failingProcs{}))
		_, err = indeterminate.ReleaseIfTerminated(ctx, s2.ID)
		f.wantRefused(err, ErrNotTerminated)
		if !f.slotHeld(s2.ID) {
			t.Fatal("an indeterminate process check released the slot")
		}
		f.procs.alive[4242] = "999" // the PID was reused by another process
		res, err := f.store.ReleaseIfTerminated(ctx, s2.ID)
		if err != nil || !res.Released || len(res.Blocks) != 1 {
			t.Fatalf("termination: %+v, %v", res, err)
		}
		if f.slotHeld(s2.ID) {
			t.Fatal("termination did not release the slot")
		}
		f.wantMode(c, h, p2, ModeBlocked)
		for _, bad := range []struct {
			pid   int
			start string
		}{{0, "1"}, {-1, "1"}, {1, ""}} {
			if _, err := (LocalProcesses{}).Alive(bad.pid, bad.start); err == nil {
				t.Fatalf("Alive(%d, %q) gave an answer for an incomplete identity", bad.pid, bad.start)
			}
		}
	})
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
			f.activate(c, h, pw(1))
			f.activate(c, h, pw(2))
			sub := f.reserve(c, h, pw(1), KindOrdinary)
			f.settle(sub.ID, OutcomeAmbiguous)
			for _, s := range []Secret{pw(1), pw(2), pw(9)} {
				f.wantMode(c, h, s, ModeBlocked)
			}
		})
		for _, o := range []Outcome{OutcomeNotSubmitted, OutcomeLocalDecryptFailed} {
			for _, k := range []Kind{KindOrdinary, KindVerification} {
				t.Run(fmt.Sprintf("%s on a %s changes nothing", o, k), func(t *testing.T) {
					f := newFixture(t)
					h := f.host()
					c := f.cred("ops")
					if k == KindOrdinary {
						f.activate(c, h, pw(1))
					}
					before := f.count(`SELECT count(*) FROM credprotect_restrictions`)
					sub := f.reserve(c, h, pw(1), k)
					f.settle(sub.ID, o)
					if n := f.count(`SELECT count(*) FROM credprotect_restrictions`); n != before {
						t.Fatalf("%s created %d restrictions", o, n-before)
					}
				})
			}
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
		t.Run("a failed verification starts a cooldown and uses the allowance", func(t *testing.T) {
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
			if err := f.request(c, h, pw(1)); err != nil {
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
			// The recovery ended the request: a new block is BLOCKED, not
			// VERIFYING on the old request (example H).
			f.block(c, h, pw(1))
			f.wantMode(c, h, pw(1), ModeBlocked)
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
			if _, err := f.store.EndPause(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			f.wantMode(c, h, pw(1), ModeVerifying) // the request stands
		})
		t.Run("a lateral restriction appeared after reserve", func(t *testing.T) {
			f, _, _, v := setup(t)
			// A usable directory appears, and pauses: lateral to the root's
			// verification, which now consults it.
			d := f.directory("corp", "ops", AdmissionUsable)
			if _, err := f.store.Pause(context.Background(), d, "directory maintenance"); err != nil {
				t.Fatal(err)
			}
			if res := f.settle(v.ID, OutcomeVerified); res.Recovery != uuid.Nil {
				t.Fatal("recovered although a lateral restriction appeared")
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
		t.Run("overridden, before its deadline", func(t *testing.T) {
			f, c, h, v := setup(t)
			if err := f.store.Override(context.Background(), v.ID, f.user, "owner stalled", true); err != nil {
				t.Fatal(err)
			}
			if res := f.settle(v.ID, OutcomeVerified); res.Late || res.Recovery != uuid.Nil {
				t.Fatalf("an overridden verification recovered: %+v", res)
			}
			f.wantMode(c, h, pw(1), ModeVerifying)
			again := f.reserve(c, h, pw(1), KindVerification)
			if res := f.settle(again.ID, OutcomeVerified); res.Recovery == uuid.Nil {
				t.Fatal("a later verification did not recover")
			}
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

// @ac AC-12
// AC-12: cooldown and allowance, with a controlled clock.
func TestCooldownAndAllowance(t *testing.T) {
	t.Run("system-credential-protection/AC-12", func(t *testing.T) {
		f := newFixture(t)
		h := f.host()
		c := f.cred("ops")
		p1 := pw(1)
		f.block(c, h, p1)
		if err := f.request(c, h, p1); err != nil {
			t.Fatal(err)
		}
		if err := f.request(c, h, p1); err != nil {
			t.Fatalf("a repeat request was not a no-op: %v", err)
		}
		if n := f.count(`SELECT count(*) FROM credprotect_verification_requests`); n != 1 {
			t.Fatalf("%d requests after a repeat, want 1", n)
		}
		v := f.reserve(c, h, p1, KindVerification)
		f.settle(v.ID, OutcomeUnsuccessful)
		f.wantMode(c, h, p1, ModeBlocked)
		f.wantRefused(f.request(c, h, p1), ErrCooldown)
		f.clock.Advance(Cooldown - time.Second)
		f.wantRefused(f.request(c, h, p1), ErrCooldown)
		f.clock.Advance(time.Second)
		f.wantRefused(f.request(c, h, p1), ErrAllowanceUsed)
		lc := f.localCred("ops")
		f.confirm(h, "ops")
		f.wantRefused(f.request(lc, h, p1), ErrAllowanceUsed) // inherited from the root
		f.activate(c, h, pw(2))                               // a new secret can be verified
	})
}

// @ac AC-12
// AC-12: a cooldown and used allowance on the root refuse a confirmed-local
// account's pending verification.
func TestInheritedCooldownRefusesAPendingVerification(t *testing.T) {
	t.Run("system-credential-protection/AC-12", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		rootCred, localCred := f.cred("ops"), f.localCred("ops")
		f.confirm(h, "ops")
		p1 := pw(1)
		f.block(rootCred, f.host(), p1)
		for _, c := range []uuid.UUID{rootCred, localCred} {
			if err := f.request(c, h, p1); err != nil {
				t.Fatal(err)
			}
		}
		v := f.reserve(rootCred, f.host(), p1, KindVerification)
		f.settle(v.ID, OutcomeUnsuccessful)
		f.wantMode(localCred, h, p1, ModeVerifying) // its own request is still pending
		_, err := f.store.Reserve(ctx, f.req(localCred, h, p1, KindVerification))
		f.wantRefused(err, ErrCooldown)
		f.clock.Advance(Cooldown)
		_, err = f.store.Reserve(ctx, f.req(localCred, h, p1, KindVerification))
		f.wantRefused(err, ErrAllowanceUsed)
	})
}
