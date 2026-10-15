// @spec system-credential-protection
//
// Account scope: classes, laterals, directory admission, local
// confirmation, binding intent, slot conflicts and recovery across a scope
// and a host record. The cases are those of the account scope proposal r4,
// adopted by contract r3 (features/OW-122).

package credprotect

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// hostBlock records a block on (h, ops)'s host record: h is confirmed
// local, and a local credential's ordinary attempt there is rejected. It
// returns the credential and the block.
func (f *fixture) hostBlock(h uuid.UUID, s Secret) (uuid.UUID, uuid.UUID) {
	f.t.Helper()
	lc := f.localCred("ops")
	f.confirm(h, "ops")
	return lc, f.block(lc, h, s)
}

// withdraw withdraws (h, ops)'s local confirmation.
func (f *fixture) withdraw(h uuid.UUID) {
	f.t.Helper()
	if err := f.store.WithdrawLocal(context.Background(), h, "ops"); err != nil {
		f.t.Fatal(err)
	}
}

// @ac AC-11
// AC-11: a recovery on a confirmed-local host record lifts the root's block
// for that account only.
func TestHostRecordRecoveryLiftsTheRootsBlockThereOnly(t *testing.T) {
	t.Run("system-credential-protection/AC-11", func(t *testing.T) {
		f := newFixture(t)
		h1, h2 := f.host(), f.host()
		uc := f.cred("ops")
		f.block(uc, h2, pw(1)) // on the root
		lc := f.localCred("ops")
		f.confirm(h1, "ops")
		f.wantMode(lc, h1, pw(1), ModeBlocked)
		if err := f.request(lc, h1, pw(1)); err != nil {
			t.Fatal(err)
		}
		v := f.reserve(lc, h1, pw(1), KindVerification)
		res := f.settle(v.ID, OutcomeVerified)
		if res.Recovery == uuid.Nil || res.HostRecovery != uuid.Nil {
			t.Fatalf("a confirmed-local recovery: %+v", res)
		}
		f.wantMode(lc, h1, pw(1), ModeActive)
		f.wantMode(uc, h2, pw(1), ModeBlocked) // the root keeps it
	})
}

// jointSetup leaves a host-plus-scope verification reserved: a directory
// block BD on D (from an attempt on another host) and a host block BH on
// (h, ops) (from when h was confirmed local), and a D-bound credential's
// verification on h whose snapshot holds both.
func jointSetup(t *testing.T) (f *fixture, h, d, dc uuid.UUID, v Submission, bd, bh uuid.UUID) {
	t.Helper()
	f = newFixture(t)
	h = f.host()
	_, bh = f.hostBlock(h, pw(1))
	f.withdraw(h)
	d = f.directory("corp", "ops", AdmissionUsable)
	dc = f.dirCred("ops", d)
	bd = f.block(dc, f.host(), pw(1))
	f.wantMode(dc, h, pw(1), ModeBlocked)
	if err := f.request(dc, h, pw(1)); err != nil {
		t.Fatal(err)
	}
	v = f.reserve(dc, h, pw(1), KindVerification)
	if !sameIDs(sortedIDs(v.Snapshot), sortedIDs([]uuid.UUID{bd, bh})) {
		t.Fatalf("snapshot %v, want D's and the host record's blocks", v.Snapshot)
	}
	return f, h, d, dc, v, bd, bh
}

// @ac AC-11
// AC-11: one directory verification on a host recovers both the directory
// and the host record, atomically.
func TestHostPlusScopeRecovery(t *testing.T) {
	t.Run("system-credential-protection/AC-11", func(t *testing.T) {
		t.Run("both recoveries are written", func(t *testing.T) {
			f, h, d, dc, v, bd, bh := jointSetup(t)
			res := f.settle(v.ID, OutcomeVerified)
			if res.Recovery == uuid.Nil || res.HostRecovery == uuid.Nil {
				t.Fatalf("host-plus-scope recovery: %+v", res)
			}
			for id, want := range map[uuid.UUID]uuid.UUID{res.Recovery: bd, res.HostRecovery: bh} {
				if n := f.count(`SELECT count(*) FROM credprotect_recoveries WHERE id = $1 AND lifted = ARRAY[$2::uuid]`,
					id, want); n != 1 {
					t.Fatalf("recovery %v does not name exactly its own identity's block", id)
				}
			}
			if f.count(`SELECT count(*) FROM credprotect_recoveries WHERE id = $1 AND identity_id = $2`, res.Recovery, d) != 1 {
				t.Fatal("the scope's recovery is not on D")
			}
			f.wantMode(dc, h, pw(1), ModeActive)
			uc := f.cred("ops")
			if m := f.mode(uc, h, pw(1)); m == ModeBlocked {
				t.Fatal("an unconfirmed attempt on h is still blocked by recovered blocks")
			}
		})
		t.Run("a failure between the writes leaves neither", func(t *testing.T) {
			f, h, _, dc, v, _, _ := jointSetup(t)
			saved := recoveryBetweenWrites
			t.Cleanup(func() { recoveryBetweenWrites = saved })
			recoveryBetweenWrites = func() error { return errors.New("injected failure between recovery writes") }
			if _, err := f.store.Settle(context.Background(), v.ID, OutcomeVerified); err == nil {
				t.Fatal("settlement succeeded despite the injected failure")
			}
			if n := f.count(`SELECT count(*) FROM credprotect_recoveries WHERE submission_id = $1`, v.ID); n != 0 {
				t.Fatalf("%d recovery records survived the failure", n)
			}
			if n := f.count(`SELECT count(*) FROM credprotect_submissions WHERE id = $1 AND outcome IS NULL AND slot_held`,
				v.ID); n != 1 {
				t.Fatal("the outcome or the slot release survived the failure")
			}
			f.wantMode(dc, h, pw(1), ModeVerifying)
			recoveryBetweenWrites = saved
			if res := f.settle(v.ID, OutcomeVerified); res.Recovery == uuid.Nil || res.HostRecovery == uuid.Nil {
				t.Fatalf("after the failure, settling again: %+v", res)
			}
		})
		t.Run("prevented by a new restriction, override and lateness", func(t *testing.T) {
			for name, change := range map[string]func(*fixture, uuid.UUID, Submission){
				"a new restriction on the host record": func(f *fixture, h uuid.UUID, _ Submission) {
					if _, err := f.store.Pause(context.Background(), f.hostRecordID(h), "host maintenance"); err != nil {
						f.t.Fatal(err)
					}
				},
				"override": func(f *fixture, _ uuid.UUID, v Submission) {
					if err := f.store.Override(context.Background(), v.ID, f.user, "stalled", true); err != nil {
						f.t.Fatal(err)
					}
				},
				"late": func(f *fixture, _ uuid.UUID, _ Submission) { f.clock.Advance(5 * time.Minute) },
			} {
				t.Run(name, func(t *testing.T) {
					f, h, _, _, v, _, _ := jointSetup(t)
					change(f, h, v)
					if res := f.settle(v.ID, OutcomeVerified); res.Recovery != uuid.Nil || res.HostRecovery != uuid.Nil {
						t.Fatalf("recovered: %+v", res)
					}
					if n := f.count(`SELECT count(*) FROM credprotect_recoveries WHERE submission_id = $1`, v.ID); n != 0 {
						t.Fatal("a recovery record was written")
					}
				})
			}
		})
		t.Run("a used allowance on the host record refuses it", func(t *testing.T) {
			f := newFixture(t)
			h := f.host()
			lc, _ := f.hostBlock(h, pw(1))
			if err := f.request(lc, h, pw(1)); err != nil {
				t.Fatal(err)
			}
			fail := f.reserve(lc, h, pw(1), KindVerification)
			f.settle(fail.ID, OutcomeUnsuccessful) // cooldown and allowance on the host record
			f.withdraw(h)
			f.clock.Advance(Cooldown)
			d := f.directory("corp", "ops", AdmissionUsable)
			dc := f.dirCred("ops", d)
			f.wantMode(dc, h, pw(1), ModeBlocked)
			f.wantRefused(f.request(dc, h, pw(1)), ErrAllowanceUsed)
		})
	})
}

func (f *fixture) hostRecordID(h uuid.UUID) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(),
		`SELECT id FROM credprotect_identities WHERE scope = 'local' AND host_id = $1 AND username = 'ops'`,
		h).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// @ac AC-06
// AC-06: the fence re-evaluates a directory attempt against its host
// record as it is now: a pause there since reserve refuses it.
func TestFenceSeesALateralRestrictionAddedSinceReserve(t *testing.T) {
	t.Run("system-credential-protection/AC-06", func(t *testing.T) {
		f, h, _, _, v, _, _ := jointSetup(t)
		if err := f.store.Fence(context.Background(), v.ID, Current{Active: true, Secret: pw(1)}); err != nil {
			t.Fatalf("fence before the pause: %v", err)
		}
		if _, err := f.store.Pause(context.Background(), f.hostRecordID(h), "host maintenance"); err != nil {
			t.Fatal(err)
		}
		f.wantRefused(f.store.Fence(context.Background(), v.ID, Current{Active: true, Secret: pw(1)}), ErrPaused)
	})
}

// @ac AC-09
// AC-09: a failed host-plus-scope verification starts the cooldown and uses
// the allowance on both identities it would have lifted.
func TestFailedJointVerificationUsesBothAllowances(t *testing.T) {
	t.Run("system-credential-protection/AC-09", func(t *testing.T) {
		f, h, d, _, v, _, _ := jointSetup(t)
		f.settle(v.ID, OutcomeRejected)
		hr := f.hostRecordID(h)
		for _, id := range []uuid.UUID{d, hr} {
			for _, k := range []string{"cooldown", "allowance_used"} {
				if n := f.count(`SELECT count(*) FROM credprotect_restrictions
				                  WHERE submission_id = $1 AND identity_id = $2 AND kind = $3`, v.ID, id, k); n != 1 {
					t.Fatalf("%d %s restrictions on %v, want 1", n, k, id)
				}
			}
		}
		if n := f.count(`SELECT count(*) FROM credprotect_restrictions WHERE submission_id = $1 AND kind = 'block'`,
			v.ID); n != 1 {
			t.Fatalf("%d blocks, want 1 on the scope", n)
		}
	})
}

// @ac AC-11
// AC-11: an unconfirmed attempt cannot lift a directory's block: it is
// BLOCKED, and requesting or reserving a verification is refused.
func TestUnconfirmedCannotLiftADirectorysBlock(t *testing.T) {
	t.Run("system-credential-protection/AC-11", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h := f.host()
		d := f.directory("corp", "ops", AdmissionUsable)
		f.block(f.dirCred("ops", d), f.host(), pw(1))
		uc := f.cred("ops")
		f.wantMode(uc, h, pw(1), ModeBlocked)
		f.wantRefused(f.request(uc, h, pw(1)), ErrLateralBlock)
		_, err := f.store.Reserve(ctx, f.req(uc, h, pw(1), KindVerification))
		f.wantRefused(err, ErrLateralBlock)
	})
}

// @ac AC-13
// AC-13: directory admission.
func TestDirectoryAdmission(t *testing.T) {
	t.Run("system-credential-protection/AC-13", func(t *testing.T) {
		t.Run("concurrent creation leaves one usable", func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			got := race(8, func(i int) error {
				_, _, err := f.store.CreateDirectory(ctx, fmt.Sprintf("corp-%d", i), "ops")
				return err
			})
			if got[nil] != 8 {
				t.Fatalf("creations: %v", got)
			}
			if n := f.count(`SELECT count(*) FROM credprotect_identities WHERE admission = 'usable'`); n != 1 {
				t.Fatalf("%d usable directory identities, want 1", n)
			}
		})
		t.Run("a candidate admits nothing", func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			h := f.host()
			f.directory("corp", "ops", AdmissionUsable)
			cand := f.directory("corp-2", "ops", AdmissionCandidate)
			cc := f.dirCred("ops", cand)
			_, err := f.store.Reserve(ctx, f.req(cc, h, pw(1), KindVerification))
			f.wantRefused(err, ErrCandidate)
			_, err = f.store.Pause(ctx, cand, "r")
			f.wantRefused(err, ErrCandidate)
			f.wantRefused(f.request(cc, h, pw(1)), ErrCandidate)
			if n := f.count(`SELECT count(*) FROM credprotect_restrictions WHERE identity_id = $1`, cand) +
				f.count(`SELECT count(*) FROM credprotect_submissions WHERE identity_id = $1`, cand); n != 0 {
				t.Fatal("a candidate gained protection history")
			}
		})
		t.Run("an assertion over a stale set is refused", func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			d1 := f.directory("corp", "ops", AdmissionUsable)
			c2 := f.directory("corp-2", "ops", AdmissionCandidate)
			c3 := f.directory("corp-3", "ops", AdmissionCandidate)
			f.wantRefused(f.store.AssertDistinct(ctx, c2, nil, f.user, "separate forest"), ErrStaleAssertion)
			f.wantRefused(f.store.AssertDistinct(ctx, c2, []uuid.UUID{d1}, f.user, ""), ErrInvalid)
			if err := f.store.AssertDistinct(ctx, c2, []uuid.UUID{d1}, f.user, "separate forest"); err != nil {
				t.Fatal(err)
			}
			// c3 was reviewed against {d1}, but c2 has become usable since.
			f.wantRefused(f.store.AssertDistinct(ctx, c3, []uuid.UUID{d1}, f.user, "separate forest"), ErrStaleAssertion)
			if err := f.store.AssertDistinct(ctx, c3, []uuid.UUID{d1, c2}, f.user, "separate forest"); err != nil {
				t.Fatal(err)
			}
			if n := f.count(`SELECT count(*) FROM credprotect_directory_resolutions WHERE resolution = 'distinct'`); n != 2 {
				t.Fatalf("%d distinct resolutions recorded, want 2", n)
			}
		})
		t.Run("asserted distinct directories run independently", func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			d1 := f.directory("corp", "ops", AdmissionUsable)
			d2 := f.directory("corp-2", "ops", AdmissionCandidate)
			if err := f.store.AssertDistinct(ctx, d2, []uuid.UUID{d1}, f.user, "separate forest"); err != nil {
				t.Fatal(err)
			}
			c1, c2 := f.dirCred("ops", d1), f.dirCred("ops", d2)
			h1, h2 := f.host(), f.host()
			f.block(c1, h1, pw(1))
			f.wantMode(c2, h2, pw(1), ModeVerifying) // D1's block does not reach D2
			s1 := f.reserve(c1, h1, pw(2), KindVerification)
			s2 := f.reserve(c2, h2, pw(2), KindVerification) // no slot conflict
			uc := f.cred("ops")
			_, err := f.store.Reserve(ctx, f.req(uc, f.host(), pw(3), KindVerification))
			f.wantRefused(err, ErrSlotBusy) // an unconfirmed attempt conflicts with both
			f.settle(s1.ID, OutcomeNotSubmitted)
			f.settle(s2.ID, OutcomeNotSubmitted)
			f.wantMode(uc, f.host(), pw(1), ModeBlocked) // and respects D1's block
		})
		t.Run("resolved as the same", func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			h1, h2 := f.host(), f.host()
			d := f.directory("corp", "ops", AdmissionUsable)
			cand := f.directory("corp-alias", "ops", AdmissionCandidate)
			dc, cc := f.dirCred("ops", d), f.dirCred("ops", cand)
			f.block(dc, h1, pw(1))
			if err := f.store.ResolveSame(ctx, cand, d, f.user, "same forest, second name"); err != nil {
				t.Fatal(err)
			}
			if f.identity(cc, h2) != d {
				t.Fatal("the candidate's credential does not resolve to the usable identity")
			}
			f.wantMode(cc, h2, pw(1), ModeBlocked) // shares D's block
			held := f.reserve(dc, h1, pw(2), KindVerification)
			_, err := f.store.Reserve(ctx, f.req(cc, h2, pw(3), KindVerification))
			f.wantRefused(err, ErrSlotBusy) // and its slot
			f.settle(held.ID, OutcomeRejected)
			f.clock.Advance(Cooldown)
			f.wantRefused(f.request(cc, h2, pw(2)), ErrAllowanceUsed) // and its allowance
		})
		t.Run("a candidate with history cannot be resolved as the same", func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			d := f.directory("corp", "ops", AdmissionUsable)
			cand := f.directory("corp-2", "ops", AdmissionCandidate)
			if _, err := f.pool.Exec(ctx, `
				INSERT INTO credprotect_restrictions (id, identity_id, kind, reason, created_at)
				VALUES ($1, $2, 'pause', 'planted', now())`, uuid.Must(uuid.NewV7()), cand); err != nil {
				t.Fatal(err)
			}
			f.wantRefused(f.store.ResolveSame(ctx, cand, d, f.user, "same"), ErrCandidate)
			if n := f.count(`SELECT count(*) FROM credprotect_identities WHERE id = $1 AND admission = 'candidate'`,
				cand); n != 1 {
				t.Fatal("a refused resolution changed the candidate")
			}
		})
	})
}

// @ac AC-14
// AC-14: local confirmation and binding intent.
func TestConfirmationAndBinding(t *testing.T) {
	t.Run("system-credential-protection/AC-14", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h1, h2, h3 := f.host(), f.host(), f.host()
		d1 := f.directory("corp", "ops", AdmissionUsable)
		d2 := f.directory("corp-2", "ops", AdmissionCandidate)
		if err := f.store.AssertDistinct(ctx, d2, []uuid.UUID{d1}, f.user, "separate forest"); err != nil {
			t.Fatal(err)
		}
		c1, c2 := f.dirCred("ops", d1), f.dirCred("ops", d2)
		s := f.reserve(c1, h1, pw(1), KindVerification) // records intent (h1, ops, d1)
		for name, change := range map[string]error{
			"classify":        f.store.Classify(ctx, f.cred("ops"), Target{Scope: ScopeLocal}),
			"confirm local":   f.store.ConfirmLocal(ctx, h2, "ops", f.user, "b"),
			"withdraw local":  f.store.WithdrawLocal(ctx, h2, "ops"),
			"assert distinct": f.store.AssertDistinct(ctx, f.directory("corp-3", "ops", AdmissionCandidate), []uuid.UUID{d1, d2}, f.user, "b"),
		} {
			if !errors.Is(change, ErrOutstanding) {
				t.Fatalf("%s while an attempt is outstanding: %v", name, change)
			}
		}
		f.settle(s.ID, OutcomeNotSubmitted)
		// An override frees the slot but still counts in o: binding changes wait.
		o := f.reserve(c1, h1, pw(2), KindVerification)
		if err := f.store.Override(ctx, o.ID, f.user, "stalled", true); err != nil {
			t.Fatal(err)
		}
		f.wantRefused(f.store.Classify(ctx, f.cred("ops"), Target{Scope: ScopeLocal}), ErrOutstanding)
		f.settle(o.ID, OutcomeNotSubmitted)
		f.wantRefused(f.store.ConfirmLocal(ctx, h1, "ops", f.user, "b"), ErrBinding)
		_, err := f.store.Reserve(ctx, f.req(c2, h1, pw(1), KindVerification))
		f.wantRefused(err, ErrBinding) // one directory per host account
		f.confirm(h3, "ops")
		_, err = f.store.Reserve(ctx, f.req(c1, h3, pw(1), KindVerification))
		f.wantRefused(err, ErrBinding) // no directory attempt on a confirmed-local host
		f.reserve(c2, h2, pw(1), KindVerification)
	})
}

// @ac AC-14
// AC-14: withdrawing a confirmation keeps the host record's block in force.
func TestWithdrawKeepsTheHostRecordsBlock(t *testing.T) {
	t.Run("system-credential-protection/AC-14", func(t *testing.T) {
		f := newFixture(t)
		h := f.host()
		lc, _ := f.hostBlock(h, pw(1))
		f.withdraw(h)
		if c := f.status(lc, h, pw(1)).Class; c != ClassUnconfirmed {
			t.Fatalf("after withdrawal the local credential is %s, want unconfirmed", c)
		}
		f.wantMode(lc, h, pw(1), ModeBlocked)
		f.wantMode(f.cred("ops"), h, pw(1), ModeBlocked)
		f.wantMode(f.cred("ops"), f.host(), pw(1), ModeVerifying) // another host's account is not affected
	})
}

// @ac AC-15
// AC-15: slot conflicts.
func TestSlotConflicts(t *testing.T) {
	t.Run("system-credential-protection/AC-15", func(t *testing.T) {
		type attempt struct {
			cred, host uuid.UUID
		}
		cases := []struct {
			name     string
			setup    func(f *fixture) (attempt, attempt)
			conflict bool
		}{
			{"one directory through two hosts", func(f *fixture) (attempt, attempt) {
				d := f.directory("corp", "ops", AdmissionUsable)
				return attempt{f.dirCred("ops", d), f.host()}, attempt{f.dirCred("ops", d), f.host()}
			}, true},
			{"distinct directories", func(f *fixture) (attempt, attempt) {
				d1 := f.directory("corp", "ops", AdmissionUsable)
				d2 := f.directory("corp-2", "ops", AdmissionCandidate)
				if err := f.store.AssertDistinct(context.Background(), d2, []uuid.UUID{d1}, f.user, "b"); err != nil {
					f.t.Fatal(err)
				}
				return attempt{f.dirCred("ops", d1), f.host()}, attempt{f.dirCred("ops", d2), f.host()}
			}, false},
			{"unconfirmed on two hosts", func(f *fixture) (attempt, attempt) {
				return attempt{f.cred("ops"), f.host()}, attempt{f.localCred("ops"), f.host()}
			}, true},
			{"directory and unconfirmed", func(f *fixture) (attempt, attempt) {
				d := f.directory("corp", "ops", AdmissionUsable)
				return attempt{f.dirCred("ops", d), f.host()}, attempt{f.cred("ops"), f.host()}
			}, true},
			{"confirmed local and unconfirmed, same host", func(f *fixture) (attempt, attempt) {
				h := f.host()
				lc := f.localCred("ops")
				f.confirm(h, "ops")
				return attempt{lc, h}, attempt{f.cred("ops"), h}
			}, true},
			{"confirmed local and unconfirmed, other host", func(f *fixture) (attempt, attempt) {
				h := f.host()
				lc := f.localCred("ops")
				f.confirm(h, "ops")
				return attempt{lc, h}, attempt{f.cred("ops"), f.host()}
			}, false},
			{"confirmed local accounts on two hosts", func(f *fixture) (attempt, attempt) {
				h1, h2 := f.host(), f.host()
				lc := f.localCred("ops")
				f.confirm(h1, "ops")
				f.confirm(h2, "ops")
				return attempt{lc, h1}, attempt{lc, h2}
			}, false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				f := newFixture(t)
				a, b := c.setup(f)
				for _, order := range [][2]attempt{{a, b}, {b, a}} {
					first := f.reserve(order[0].cred, order[0].host, pw(1), KindVerification)
					second, err := f.store.Reserve(context.Background(),
						f.req(order[1].cred, order[1].host, pw(2), KindVerification))
					if c.conflict && !errors.Is(err, ErrSlotBusy) {
						t.Fatalf("expected a conflict, got %v", err)
					}
					if !c.conflict && err != nil {
						t.Fatalf("expected no conflict, got %v", err)
					}
					f.settle(first.ID, OutcomeNotSubmitted)
					if err == nil {
						f.settle(second.ID, OutcomeNotSubmitted)
					}
				}
			})
		}
	})
}

// @ac AC-16
// AC-16: account history reaches every attempt that may reach the account.
func TestAccountHistory(t *testing.T) {
	t.Run("system-credential-protection/AC-16", func(t *testing.T) {
		roundTrip := func(f *fixture, c uuid.UUID) {
			f.t.Helper()
			ctx := context.Background()
			for _, u := range []string{"other", "ops"} {
				if _, err := f.pool.Exec(ctx, `UPDATE credentials SET username = $2 WHERE id = $1`, c, u); err != nil {
					f.t.Fatal(err)
				}
				if u == "other" {
					f.classify(c, Target{Scope: ScopeLocal})
				}
			}
		}
		t.Run("a root block from an unconfirmed local credential", func(t *testing.T) {
			f := newFixture(t)
			h := f.host()
			lc := f.localCred("ops")
			f.block(lc, h, pw(1)) // h is not confirmed: recorded on the root
			f.wantMode(f.cred("ops"), h, pw(1), ModeBlocked)
			roundTrip(f, lc)
			f.wantMode(lc, h, pw(1), ModeBlocked)
		})
		t.Run("a host block from a confirmed-local account", func(t *testing.T) {
			f := newFixture(t)
			h := f.host()
			lc, bh := f.hostBlock(h, pw(1))
			if f.count(`SELECT count(*) FROM credprotect_restrictions WHERE id = $1 AND identity_id = $2`,
				bh, f.hostRecordID(h)) != 1 {
				t.Fatal("the block is not on the host record")
			}
			f.wantMode(f.cred("ops"), h, pw(1), ModeBlocked) // an unconfirmed duplicate consults it
			roundTrip(f, lc)
			f.wantMode(lc, h, pw(1), ModeBlocked)
		})
		t.Run("a directory's rejection", func(t *testing.T) {
			f := newFixture(t)
			d := f.directory("corp", "ops", AdmissionUsable)
			f.block(f.dirCred("ops", d), f.host(), pw(1))
			f.wantMode(f.dirCred("ops", d), f.host(), pw(1), ModeBlocked)
			f.wantMode(f.cred("ops"), f.host(), pw(1), ModeBlocked)
			// A local classification on a host that is not confirmed is
			// unconfirmed, and meets it too.
			f.wantMode(f.localCred("ops"), f.host(), pw(1), ModeBlocked)
		})
		t.Run("a local classification meets a directory's slot", func(t *testing.T) {
			f := newFixture(t)
			d := f.directory("corp", "ops", AdmissionUsable)
			lc := f.localCred("ops") // classified before: binding changes wait for outstanding attempts
			held := f.reserve(f.dirCred("ops", d), f.host(), pw(1), KindVerification)
			_, err := f.store.Reserve(context.Background(), f.req(lc, f.host(), pw(2), KindVerification))
			f.wantRefused(err, ErrSlotBusy)
			f.settle(held.ID, OutcomeNotSubmitted)
		})
		t.Run("separate confirmed-local accounts", func(t *testing.T) {
			f := newFixture(t)
			h1, h2 := f.host(), f.host()
			lc, _ := f.hostBlock(h1, pw(1))
			f.confirm(h2, "ops")
			f.wantMode(lc, h1, pw(1), ModeBlocked)
			f.wantMode(lc, h2, pw(1), ModeVerifying)
		})
	})
}

// @ac AC-13
// AC-13: competing resolutions of one candidate, queued on the username's
// lock, make exactly one transition; the other is refused and changes
// nothing (review round 3, finding 1).
func TestCompetingResolutionsMakeOneTransition(t *testing.T) {
	t.Run("system-credential-protection/AC-13", func(t *testing.T) {
		type resolution func(f *fixture, cand, d uuid.UUID) error
		distinct := func(f *fixture, cand, d uuid.UUID) error {
			return f.store.AssertDistinct(context.Background(), cand, []uuid.UUID{d}, f.user, "separate forest")
		}
		same := func(f *fixture, cand, d uuid.UUID) error {
			return f.store.ResolveSame(context.Background(), cand, d, f.user, "same forest")
		}
		for name, c := range map[string]struct {
			first, second resolution
			admission     Admission
			moved         bool
		}{
			"distinct, then same":     {distinct, same, AdmissionUsable, false},
			"same, then distinct":     {same, distinct, AdmissionRetired, true},
			"distinct, then distinct": {distinct, distinct, AdmissionUsable, false},
		} {
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				d := f.directory("corp", "ops", AdmissionUsable)
				cand := f.directory("corp-2", "ops", AdmissionCandidate)
				cc := f.dirCred("ops", cand)
				release := f.holdLock("ops")
				first, second := make(chan error, 1), make(chan error, 1)
				go func() { first <- c.first(f, cand, d) }()
				f.waitForLockWaiters(1)
				go func() { second <- c.second(f, cand, d) }()
				f.waitForLockWaiters(2)
				release()
				if err := <-first; err != nil {
					t.Fatalf("the first resolution: %v", err)
				}
				f.wantRefused(<-second, ErrInvalid)
				if n := f.count(`SELECT count(*) FROM credprotect_identities WHERE id = $1 AND admission = $2`,
					cand, string(c.admission)); n != 1 {
					t.Fatalf("the candidate is not %s", c.admission)
				}
				movedTo := f.count(`SELECT count(*) FROM credprotect_credential_classes WHERE credential_id = $1
				                     AND directory_identity_id = $2`, cc, d) == 1
				if movedTo != c.moved {
					t.Fatalf("credentials moved = %v, want %v", movedTo, c.moved)
				}
				if n := f.count(`SELECT count(*) FROM credprotect_directory_resolutions WHERE directory_id = $1`, cand); n != 1 {
					t.Fatalf("%d resolutions recorded, want 1", n)
				}
			})
		}
		t.Run("each update itself requires a candidate", func(t *testing.T) {
			// Run the production statements directly against a directory that
			// is no longer a candidate: each must change nothing and refuse.
			f := newFixture(t)
			ctx := context.Background()
			d := f.directory("corp", "ops", AdmissionUsable)
			other := f.directory("corp-2", "ops", AdmissionCandidate)
			if err := f.store.AssertDistinct(ctx, other, []uuid.UUID{d}, f.user, "separate forest"); err != nil {
				t.Fatal(err)
			}
			for name, run := range map[string]func(tx pgx.Tx) error{
				"admit":  func(tx pgx.Tx) error { return resolveCandidate(ctx, tx, admitCandidateSQL, other) },
				"retire": func(tx pgx.Tx) error { return resolveCandidate(ctx, tx, retireCandidateSQL, other, d) },
			} {
				tx, err := f.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				err = run(tx)
				_ = tx.Rollback(ctx)
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("%s on a usable identity: %v, want ErrInvalid", name, err)
				}
			}
		})
	})
}

// waitForLockWaiters waits until at least n sessions in this test database
// are waiting for an advisory lock.
func (f *fixture) waitForLockWaiters(n int) {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if f.count(`SELECT count(*) FROM pg_locks
		             WHERE locktype = 'advisory' AND NOT granted
		               AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`) >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.t.Fatalf("fewer than %d calls waited for the username's lock", n)
}

// @ac AC-06
// AC-06: a block that appears while a requested verification is in flight
// refuses its fence, although the pending request keeps the mode VERIFYING
// (review round 3, finding 2). The block comes from an unconfirmed attempt
// on another host, which does not conflict with the confirmed-local
// verification, and lands on the root, in the verification's lineage.
func TestFenceRefusesANewBlockDuringARequestedVerification(t *testing.T) {
	t.Run("system-credential-protection/AC-06", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		h, other := f.host(), f.host()
		f.confirm(h, "ops")
		lc, uc := f.localCred("ops"), f.cred("ops")
		f.block(lc, h, pw(1))
		if err := f.request(lc, h, pw(1)); err != nil {
			t.Fatal(err)
		}
		f.activate(uc, other, pw(1))
		run := f.reserve(uc, other, pw(1), KindOrdinary)
		v := f.reserve(lc, h, pw(1), KindVerification)
		if err := f.store.Fence(ctx, v.ID, Current{Active: true, Secret: pw(1)}); err != nil {
			t.Fatalf("fence before the new block: %v", err)
		}
		f.settle(run.ID, OutcomeRejected)
		f.wantMode(lc, h, pw(1), ModeVerifying) // the pending request keeps it VERIFYING
		f.wantRefused(f.store.Fence(ctx, v.ID, Current{Active: true, Secret: pw(1)}), ErrFenceRefused)
		if res := f.settle(v.ID, OutcomeVerified); res.Recovery != uuid.Nil {
			t.Fatal("recovered past the new block")
		}
	})
}
