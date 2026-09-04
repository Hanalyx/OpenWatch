// @spec system-scheduler
//
// bugs/OW-024, the persisted half. OW-023 has no equivalent: drift computes a
// score per evaluation and stores none, so fixing its producer is the whole
// fix. The scheduler writes, so its rows carry the fabricated value until
// something repairs them.
//
// One composite test covers AC-21. Both halves, the repair and the abort, load
// the same fixtures from the spec; nothing is reconstructed in Go and Raw() is
// not used, because marking a field consumed is not the same as proving it was
// used.
package db_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// ow024Fixture is one seeded host: the scan that ran, the row the buggy
// producer wrote, and what the repair must leave behind.
type ow024Fixture struct {
	hostID        uuid.UUID
	name          string
	completedScan bool
	// counts holds the scan run outcome counts. A nil entry is a NULL column:
	// a completed run whose counts were never recorded. That is missing
	// evidence, not evidence of zero, and the repair must leave it alone.
	counts map[string]*int

	storedState       string
	storedScore       *float64
	storedHasCritical bool
	nextScan          time.Time

	wantState    string
	wantScoreSet bool
	wantScore    float64
	wantRepaired bool
}

func f64(v float64) *float64 { return &v }

// parseFixture reads one fixture entry, consuming every field.
func parseFixture(t *testing.T, f *specfixture.Fields, now time.Time) ow024Fixture {
	t.Helper()
	out := ow024Fixture{
		name:          f.Str("name"),
		completedScan: f.Bool("completed_scan"),
		counts:        map[string]*int{},
		nextScan:      now.Add(4 * time.Hour),
	}
	c := f.Map("counts")
	for _, k := range []string{"pass", "fail", "skipped", "error"} {
		if c.IsNullable(k) {
			c.IsNull(k)
			out.counts[k] = nil
			continue
		}
		n := c.Int(k)
		out.counts[k] = &n
	}
	c.AllConsumed()

	st := f.Map("stored")
	out.storedState = st.Str("state")
	if st.IsNullable("score") {
		st.IsNull("score")
	} else {
		out.storedScore = f64(st.Num("score"))
	}
	out.storedHasCritical = st.Bool("has_critical_findings")
	st.AllConsumed()

	ex := f.Map("expect")
	out.wantState = ex.Str("state")
	if ex.IsNullable("score") {
		ex.IsNull("score")
	} else {
		out.wantScoreSet = true
		out.wantScore = ex.Num("score")
	}
	out.wantRepaired = ex.Bool("repaired")
	ex.AllConsumed()

	f.AllConsumed()
	return out
}

// @ac AC-21
// AC-21: the repair corrects rows the buggy producer wrote, selecting on the
// outcome counts of the latest completed scan rather than on the stored zero.
//
// Two fixtures do the discriminating work. genuine-zero has a real zero percent
// and must survive untouched: the development fleet holds no such host, so a
// migration written with `compliance_score = 0` passes every run against dev and
// silently relabels a genuinely non-compliant host. completed-zero-outcomes has
// a completed scan that produced NO outcomes, so it has no rule-state rows at
// all: a predicate written against rule state misses it entirely and leaves the
// fabricated critical row in place.
func TestOW024Repair(t *testing.T) {
	t.Run("system-scheduler/AC-21", func(t *testing.T) {
		ctx := context.Background()
		now := time.Now().UTC().Truncate(time.Second)

		ac := specfixture.Get(t, schedulerCriteria(t), "AC-21")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		var fixtures []ow024Fixture
		for _, f := range in.MapList("fixtures") {
			fixtures = append(fixtures, parseFixture(t, f, now))
		}
		conflicting := parseFixture(t, in.Map("conflicting_fixture"), now)
		runs := in.Int("runs")
		if runs < 2 {
			t.Fatalf("runs = %d; idempotence needs at least two", runs)
		}
		wantPreserved := exp.Bool("has_critical_findings_preserved")
		wantMovedLater := exp.Bool("next_scheduled_scan_moved_later")
		wantIdempotent := exp.Bool("idempotent")
		wantAborts := exp.Bool("conflicting_critical_aborts")
		wantUnrepaired := exp.Bool("conflicting_critical_leaves_rows_unrepaired")
		wantTransactional := exp.Bool("transactional")
		in.AllConsumed()
		exp.AllConsumed()

		// --- the repair, run `runs` times to prove idempotence ---
		t.Run("repairs", func(t *testing.T) {
			pool := dbtest.Pool(t)
			createdBy := seedOW024User(t, ctx, pool)
			for i := range fixtures {
				fixtures[i].hostID = seedOW024Host(t, ctx, pool, fixtures[i], now, createdBy)
			}

			for pass := 1; pass <= runs; pass++ {
				if err := runOW024Repair(ctx, pool, t); err != nil {
					t.Fatalf("pass %d: %v", pass, err)
				}
				for _, f := range fixtures {
					state, score, hasCritical, nextScan := readSchedule(t, ctx, pool, f.hostID)

					if state != f.wantState {
						t.Errorf("pass %d: %s state = %q, want %q", pass, f.name, state, f.wantState)
					}
					if f.wantScoreSet {
						if score == nil || *score != f.wantScore {
							t.Errorf("pass %d: %s score = %v, want %v", pass, f.name, score, f.wantScore)
						}
					} else if score != nil {
						t.Errorf("pass %d: %s score = %v, want NULL", pass, f.name, *score)
					}
					// repaired restates the same claim from the other side, so a
					// fixture whose two halves disagree fails rather than
					// quietly asserting only one of them.
					if repaired := state != f.storedState; repaired != f.wantRepaired {
						t.Errorf("pass %d: %s repaired = %v, want %v", pass, f.name, repaired, f.wantRepaired)
					}
					if wantPreserved && hasCritical != f.storedHasCritical {
						t.Errorf("pass %d: %s has_critical_findings = %v, want %v", pass, f.name, hasCritical, f.storedHasCritical)
					}
					if !wantMovedLater && nextScan.After(f.nextScan) {
						t.Errorf("pass %d: %s next_scheduled_scan moved later", pass, f.name)
					}
				}
				if pass > 1 && !wantIdempotent {
					t.Fatal("fixture ran the repair twice but does not claim idempotence")
				}
			}
		})

		// --- transactional: an abort rolls back a repair in the same transaction ---
		t.Run("transactional", func(t *testing.T) {
			// The claim is checked against the file, not just consumed. goose
			// wraps a migration in a transaction unless it declares
			// "-- +goose NO TRANSACTION", so whether this migration is
			// transactional is a fact about the file. A fixture flipped to
			// false to dodge a failure therefore fails instead of skipping.
			optedOut := migrationOptsOutOfTransaction(t)
			if wantTransactional == optedOut {
				t.Fatalf("fixture says transactional=%v but the migration %s",
					wantTransactional,
					map[bool]string{true: "declares NO TRANSACTION", false: "runs in one"}[optedOut])
			}
			if !wantTransactional {
				t.Skip("migration declares NO TRANSACTION and the fixture agrees")
			}
			pool := dbtest.Pool(t)
			createdBy := seedOW024User(t, ctx, pool)

			// One repairable host and one conflicting host in the same run. If
			// the body is transactional, the abort rolls the repair back too.
			// Statement ordering alone would not prove this: the precondition
			// runs first, so it would prevent the UPDATE rather than undo it.
			// Running the UPDATE first inside the transaction is what makes the
			// rollback observable.
			var repairable ow024Fixture
			for _, f := range fixtures {
				if f.wantRepaired {
					repairable = f
					break
				}
			}
			if repairable.name == "" {
				t.Fatal("no repairable fixture to roll back")
			}
			rid := seedOW024Host(t, ctx, pool, repairable, now, createdBy)
			seedOW024Host(t, ctx, pool, conflicting, now, createdBy)

			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback(ctx) }()

			stmts := upStatements(t)
			// Apply the repair first, then the precondition, inside one
			// transaction. The repair lands, the precondition aborts, and the
			// transaction must undo the repair.
			var abortErr error
			for _, stmt := range []string{stmts[1], stmts[0]} {
				if _, err := tx.Exec(ctx, stmt); err != nil {
					abortErr = err
					break
				}
			}
			if abortErr == nil {
				t.Fatal("precondition did not abort with a conflicting row present")
			}
			_ = tx.Rollback(ctx)

			state, score, _, _ := readSchedule(t, ctx, pool, rid)
			if state != repairable.storedState || score == nil {
				t.Errorf("%s was left repaired after an aborted transaction: state=%q score=%v; the repair must roll back",
					repairable.name, state, derefScore(score))
			}
		})

		// --- the abort, from the same spec fixture ---
		t.Run("aborts-on-conflicting-critical", func(t *testing.T) {
			pool := dbtest.Pool(t)
			createdBy := seedOW024User(t, ctx, pool)
			id := seedOW024Host(t, ctx, pool, conflicting, now, createdBy)

			err := runOW024Repair(ctx, pool, t)
			if (err != nil) != wantAborts {
				t.Fatalf("abort = %v, want %v (err = %v)", err != nil, wantAborts, err)
			}
			state, score, _, _ := readSchedule(t, ctx, pool, id)
			unrepaired := state == conflicting.storedState &&
				score != nil && conflicting.storedScore != nil && *score == *conflicting.storedScore
			if unrepaired != wantUnrepaired {
				t.Errorf("left unrepaired = %v, want %v (state=%q score=%v)", unrepaired, wantUnrepaired, state, derefScore(score))
			}
			if state != conflicting.wantState {
				t.Errorf("state = %q, want %q", state, conflicting.wantState)
			}
		})
	})
}

// nullableInt turns a nil count into a SQL NULL rather than a zero.
func nullableInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func derefScore(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func readSchedule(t *testing.T, ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID) (string, *float64, bool, time.Time) {
	t.Helper()
	var state string
	var score *float64
	var hasCritical bool
	var nextScan time.Time
	if err := pool.QueryRow(ctx, `
		SELECT compliance_state, compliance_score, has_critical_findings, next_scheduled_scan
		  FROM host_compliance_schedule WHERE host_id = $1`, hostID).
		Scan(&state, &score, &hasCritical, &nextScan); err != nil {
		t.Fatalf("read schedule: %v", err)
	}
	return state, score, hasCritical, nextScan
}

func seedOW024User(t *testing.T, ctx context.Context, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash)
		VALUES ($1, $2, $3, $4)`,
		// Full uuid, not a prefix: uuid.NewV7 is timestamp-ordered, so two ids
		// minted in the same millisecond share their first characters and trip
		// the unique username index.
		id, "ow024-"+id.String(), "ow024-"+id.String()+"@example.com", "argon2id$dummy"); err != nil { // pragma: allowlist secret
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// seedOW024Host inserts the host, its completed scan run with that run's outcome
// counts, any rule state those counts imply, and the schedule row the buggy
// producer would have written.
//
// The scan run is created from completed_scan, NOT from whether there are
// outcomes. A completed scan that produced zero outcomes is a real and distinct
// case from never having been scanned, and conflating them is what hid the
// migration defect this fixture exists to catch.
func seedOW024Host(t *testing.T, ctx context.Context, pool *pgxpool.Pool, f ow024Fixture, now time.Time, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	hostID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO hosts (id, hostname, ip_address, created_by)
		VALUES ($1, $2, '127.0.0.1'::inet, $3)`,
		hostID, f.name+"-"+hostID.String()[:8], createdBy); err != nil {
		t.Fatalf("seed host %s: %v", f.name, err)
	}

	if f.completedScan {
		scanID := uuid.New()
		if _, err := pool.Exec(ctx, `
			INSERT INTO scan_runs
				(id, host_id, trigger_source, status, queued_at, started_at, finished_at,
				 rules_pass, rules_fail, rules_skipped, rules_error)
			VALUES ($1, $2, 'scheduled', 'completed', $3, $3, $3, $4, $5, $6, $7)`,
			scanID, hostID, now,
			nullableInt(f.counts["pass"]), nullableInt(f.counts["fail"]),
			nullableInt(f.counts["skipped"]), nullableInt(f.counts["error"])); err != nil {
			t.Fatalf("seed scan_run %s: %v", f.name, err)
		}
		n := 0
		for _, status := range []string{"pass", "fail", "skipped", "error"} {
			c := f.counts[status]
			if c == nil {
				continue
			}
			for i := 0; i < *c; i++ {
				n++
				if _, err := pool.Exec(ctx, `
					INSERT INTO host_rule_state
						(host_id, rule_id, current_status, last_checked_at, last_scan_id,
						 first_seen_at, last_changed_at)
					VALUES ($1, $2, $3, $4, $5, $4, $4)`,
					hostID, fmt.Sprintf("rule-%s-%d", status, n), status, now, scanID); err != nil {
					t.Fatalf("seed rule state %s/%s: %v", f.name, status, err)
				}
			}
		}
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO host_compliance_schedule
			(host_id, compliance_state, compliance_score, has_critical_findings,
			 current_interval_minutes, next_scheduled_scan, last_scan_completed_at, updated_at)
		VALUES ($1, $2, $3, $4, 240, $5, $6, now())`,
		hostID, f.storedState, f.storedScore, f.storedHasCritical, f.nextScan, now); err != nil {
		t.Fatalf("seed schedule %s: %v", f.name, err)
	}
	return hostID
}

// upStatements returns every statement in the migration Up section, in order.
//
// The whole Up body runs, not just the repair. An earlier version extracted the
// UPDATE alone, so the precondition that aborts on a conflicting
// has_critical_findings row shipped untested: the guard existed and nothing had
// ever seen it fire. Statements are read from the file rather than restated, so
// this test cannot pass against a repair that differs from the one that ships.
func upStatements(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("migrations/0061_repair_fabricated_unassessable_scores.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	body := string(raw)
	up := body[strings.Index(body, "-- +goose Up"):strings.Index(body, "-- +goose Down")]

	var out []string
	if b := strings.Index(up, "-- +goose StatementBegin"); b >= 0 {
		e := strings.Index(up, "-- +goose StatementEnd")
		if e < 0 {
			t.Fatal("StatementBegin without StatementEnd")
		}
		out = append(out, strings.TrimSpace(up[b+len("-- +goose StatementBegin"):e]))
		up = up[e+len("-- +goose StatementEnd"):]
	}
	for _, stmt := range strings.Split(up, ";") {
		if s := strings.TrimSpace(stripSQLComments(stmt)); s != "" {
			out = append(out, s+";")
		}
	}
	if len(out) < 2 {
		t.Fatalf("migration Up yielded %d statements, want the precondition and the repair", len(out))
	}
	return out
}

// migrationOptsOutOfTransaction reports whether the migration declares
// "-- +goose NO TRANSACTION", which is the only way it runs unwrapped.
func migrationOptsOutOfTransaction(t *testing.T) bool {
	t.Helper()
	raw, err := os.ReadFile("migrations/0061_repair_fabricated_unassessable_scores.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	return strings.Contains(string(raw), "+goose NO TRANSACTION")
}

// stripSQLComments removes whole-line -- comments so a trailing comment block is
// not mistaken for a statement.
func stripSQLComments(s string) string {
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

// runOW024Repair executes the migration Up body and returns the first error.
func runOW024Repair(ctx context.Context, pool *pgxpool.Pool, t *testing.T) error {
	t.Helper()
	for _, stmt := range upStatements(t) {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// schedulerCriteria loads the scheduler spec criteria.
func schedulerCriteria(t *testing.T) map[string]specfixture.Criterion {
	t.Helper()
	return specfixture.Load(t, "../../specs/system/scheduler.spec.yaml", "system-scheduler")
}
