// @spec system-current-corpus
//
// AC traceability (DSN-gated):
//
//	AC-20  TestSeedHelper_ProducesARealCorpus
//
// WHY THIS FILE EXISTS. Every other test in the tree that touches
// compliance now trusts this package to put its rows IN a corpus. If it
// quietly stopped doing that, nothing would go red: counts would come
// back zero, ratios nil, list summaries null, and every one of those
// reads exactly like a host nobody has scanned. A suite of hundreds of
// assertions would pass by comparing nothing against nothing.
//
// So the helper's own promise is asserted here, directly, against the
// view rather than against the fixture that produced it.

package corpustest

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE host_rule_state CASCADE",
		"TRUNCATE TABLE scan_runs CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "ct-"+id.String(), "ct-"+id.String()+"@example.com",
		"argon2id$dummy") // pragma: allowlist secret
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedHost(t *testing.T, pool *pgxpool.Pool, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, '192.0.2.40'::inet, $3)`,
		id, "ct-"+id.String(), createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// corpusRules reads the rule ids the VIEW returns for a host.
//
// Reading the view rather than re-deriving the condition is the point:
// the helper's promise is that the rows land where the product looks for
// them, and only the product's own definition can confirm that.
func corpusRules(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT rule_id FROM host_rule_state_current WHERE host_id = $1 ORDER BY rule_id`, hostID)
	if err != nil {
		t.Fatalf("query view: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	return out
}

func countRows(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM host_rule_state WHERE host_id = $1`, hostID).Scan(&n); err != nil {
		t.Fatalf("count base rows: %v", err)
	}
	return n
}

// @ac AC-20
// AC-20: the seed helper produces a REAL corpus, and asking for an
// unscanned host produces an empty one.
//
// Both halves are needed and the second is not a formality. If the
// helper produced a corpus no matter what it was asked for, a test
// meaning to exercise a never-scanned host would silently exercise a
// scanned one, and the "no data, not zero percent" criteria would be
// asserting against the wrong fixture entirely.
func TestSeedHelper_ProducesARealCorpus(t *testing.T) {
	t.Run("system-current-corpus/AC-20", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)

		t.Run("SeedScanned lands rows in the corpus", func(t *testing.T) {
			host := seedHost(t, pool, user)
			scanID := SeedScanned(t, pool, host,
				Rule{RuleID: "rule-a", Status: "pass"},
				Rule{RuleID: "rule-b", Status: "fail", Severity: "high"},
				Rule{RuleID: "rule-c", Status: "skipped"},
			)

			got := corpusRules(t, pool, host)
			if len(got) != 3 {
				t.Fatalf("current corpus = %v, want all three rules. This is the assertion that "+
					"stops a suite going green by reading nothing everywhere", got)
			}
			// Named, not counted. A count of three would pass if the
			// helper seeded three of something else.
			for i, want := range []string{"rule-a", "rule-b", "rule-c"} {
				if got[i] != want {
					t.Errorf("corpus[%d] = %q, want %q", i, got[i], want)
				}
			}
			// The returned id is the run the corpus actually resolves to,
			// so a caller can seed a second scan against it meaningfully.
			var stamped uuid.UUID
			if err := pool.QueryRow(context.Background(),
				`SELECT last_scan_id FROM host_rule_state WHERE host_id = $1 AND rule_id = 'rule-a'`,
				host).Scan(&stamped); err != nil {
				t.Fatalf("read last_scan_id: %v", err)
			}
			if stamped != scanID {
				t.Errorf("row carries last_scan_id %s, but SeedScanned returned %s; a caller "+
					"naming the returned run would be naming the wrong one", stamped, scanID)
			}
		})

		t.Run("an unscanned host gets rows and no corpus", func(t *testing.T) {
			host := seedHost(t, pool, user)
			// The documented way to ask for a host with scan history and
			// no corpus: a run that is not completed.
			runID := SeedRun(t, pool, host, "running", time.Now().Add(-time.Hour), time.Time{})
			SeedRules(t, pool, host, runID,
				Rule{RuleID: "rule-a", Status: "pass"},
				Rule{RuleID: "rule-b", Status: "fail"},
			)

			if got := corpusRules(t, pool, host); len(got) != 0 {
				t.Errorf("current corpus = %v, want empty. Asking for an unscanned host must "+
					"produce one, or every no-data criterion is asserting against a scanned "+
					"fixture without saying so", got)
			}
			// The rows exist. An empty corpus and an empty table are
			// different states and this helper produces the first.
			if n := countRows(t, pool, host); n != 2 {
				t.Errorf("host_rule_state rows = %d, want 2; the point of this call is rule "+
					"state with no corpus, not a host with nothing on it", n)
			}
		})

		t.Run("CurrentRun reuses rather than competes", func(t *testing.T) {
			host := seedHost(t, pool, user)
			existing := SeedScanned(t, pool, host, Rule{RuleID: "rule-a", Status: "pass"})
			if got := CurrentRun(t, pool, host); got != existing {
				t.Errorf("CurrentRun = %s, want the existing run %s. Creating a second run here "+
					"would evict every row the first one stamped", got, existing)
			}
			if got := corpusRules(t, pool, host); len(got) != 1 {
				t.Errorf("corpus = %v after CurrentRun, want the one seeded rule still in it", got)
			}
		})

		t.Run("a run CurrentRun creates does not outrank a test's own", func(t *testing.T) {
			// The failure this pins cost a real test: a helper-created run
			// stamped at now() finished later than the run the test seeded
			// for itself, so every latest-completed read answered with the
			// helper's.
			host := seedHost(t, pool, user)
			created := CurrentRun(t, pool, host)

			// The test's run finishes THIRTY SECONDS AGO, not now.
			//
			// That number is the whole test. A run finishing at the
			// current instant wins against a helper run created moments
			// earlier no matter how the helper stamps it, so the first
			// version of this assertion passed against a helper stamping
			// now() and proved nothing. A test seeding a run in the recent
			// past is ordinary, and it is the case that separates a
			// backdated helper from one that competes.
			base := time.Now().UTC().Add(-30 * time.Second)
			mine := SeedRun(t, pool, host, "completed", base.Add(-85*time.Second), base)

			var latest uuid.UUID
			if err := pool.QueryRow(context.Background(), `
				SELECT id FROM scan_runs
				 WHERE host_id = $1 AND status = 'completed'
				 ORDER BY finished_at DESC NULLS LAST, id DESC
				 LIMIT 1`, host).Scan(&latest); err != nil {
				t.Fatalf("read latest completed: %v", err)
			}
			if latest != mine {
				t.Errorf("latest completed run = %s, want the test's own run %s (helper created %s). "+
					"A helper-created run must never outrank one the test authored, or the test "+
					"silently asserts against the helper's fixture", latest, mine, created)
			}
		})
	})
}
