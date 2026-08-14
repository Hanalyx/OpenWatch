// @spec system-current-corpus
//
// AC traceability (DSN-gated):
//
//	AC-01  TestView_ExistsAndMatchesTheTable
//	AC-22  TestIndex_ProbesPerHostWithoutASort
//
// The view and the index it depends on, asserted from the catalog and
// from the query plan rather than from behavior. Both are the kind of
// object that keeps working by accident until the day it does not.

package corpus

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// columnSet returns name -> formatted type for a relation, read from the
// catalog rather than from any migration text.
func columnSet(t *testing.T, pool *pgxpool.Pool, relation string) map[string]string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT a.attname, format_type(a.atttypid, a.atttypmod)
		  FROM pg_attribute a
		  JOIN pg_class c ON c.oid = a.attrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE c.relname = $1 AND n.nspname = 'public'
		   AND a.attnum > 0 AND NOT a.attisdropped
		 ORDER BY a.attnum`, relation)
	if err != nil {
		t.Fatalf("read columns of %s: %v", relation, err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		out[name] = typ
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns: %v", err)
	}
	return out
}

// @ac AC-01
// AC-01: the view exists, its column set equals the table's name for
// name and type for type, and it does not filter soft-deleted hosts.
//
// The column-set half is what catches a later migration adding a column
// to host_rule_state and forgetting to recreate the view. A view created
// with SELECT * expands its column list ONCE, at creation, so the two
// drift silently: every existing read keeps working and the new column
// is simply absent from the corpus view. Comparing catalogs is the only
// check that sees it.
//
// The soft-delete half is a boundary. Several callers already join hosts
// to exclude deleted ones, and one of them would filter twice if the
// view did it too. Folding a second concern into the view is how a
// one-line read starts carrying a policy nobody asked it to carry.
func TestView_ExistsAndMatchesTheTable(t *testing.T) {
	t.Run("system-current-corpus/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()

		var relkind string
		if err := pool.QueryRow(ctx, `
			SELECT c.relkind::text FROM pg_class c
			  JOIN pg_namespace n ON n.oid = c.relnamespace
			 WHERE c.relname = 'host_rule_state_current' AND n.nspname = 'public'`).Scan(&relkind); err != nil {
			t.Fatalf("host_rule_state_current not found in the catalog: %v", err)
		}
		if relkind != "v" {
			t.Errorf("host_rule_state_current has relkind %q, want v (a view)", relkind)
		}

		table := columnSet(t, pool, "host_rule_state")
		view := columnSet(t, pool, "host_rule_state_current")
		if len(table) == 0 {
			t.Fatal("host_rule_state has no columns; the catalog query is broken, not the schema")
		}

		for name, typ := range table {
			vt, ok := view[name]
			if !ok {
				t.Errorf("the view is missing column %q. A view created with SELECT * fixes its "+
					"column list at creation, so a migration that adds a column to the table and "+
					"does not recreate the view leaves it invisible to every corpus read", name)
				continue
			}
			if vt != typ {
				t.Errorf("column %q is %s in the table and %s in the view", name, typ, vt)
			}
		}
		for name := range view {
			if _, ok := table[name]; !ok {
				t.Errorf("the view has column %q that the table does not; moving a read to the "+
					"view is supposed to be a one-word change to the FROM clause", name)
			}
		}

		t.Run("the view does not filter soft-deleted hosts", func(t *testing.T) {
			user := seedUser(t, pool)
			host := seedHost(t, pool, user)
			run := seedRun(t, pool, host, "completed", hoursAgo(1), hoursAgo(1))
			seedRuleState(t, pool, host, "rule-a", "pass", run)
			if _, err := pool.Exec(ctx,
				`UPDATE hosts SET deleted_at = now() WHERE id = $1`, host); err != nil {
				t.Fatalf("soft delete: %v", err)
			}
			if got := inCorpus(t, pool, host); !equal(got, []string{"rule-a"}) {
				t.Errorf("current corpus for a soft-deleted host = %v, want [rule-a]. The view "+
					"answers which rules a host is measured against and nothing else; callers "+
					"that care about deletion already join hosts, and one of them would then "+
					"filter twice", got)
			}
		})
	})
}

// @ac AC-22
// AC-22: the corpus lookup is an index probe that stays per-host.
//
// Two halves and the second is the load-bearing one. The catalog check
// includes the NULL ORDERING, because in Postgres DESC implies NULLS
// FIRST: an index declared (finished_at DESC) has the right column and
// the right direction and still does not match an ORDER BY of
// (finished_at DESC NULLS LAST). A catalog check comparing only names
// and directions passes on that index.
//
// And the plan still looks healthy, because the planner uses the index
// anyway and puts a Sort on top. The ABSENT Sort node is therefore the
// only assertion that distinguishes the correct index from the broken
// one, which is why it is asserted rather than the wall-clock time. A
// timing threshold on a shared runner flakes, and a suite people learn
// to ignore protects nothing.
func TestIndex_ProbesPerHostWithoutASort(t *testing.T) {
	t.Run("system-current-corpus/AC-22", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()

		const indexName = "scan_runs_host_latest_completed"
		var indexDef string
		if err := pool.QueryRow(ctx,
			`SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND indexname=$1`,
			indexName).Scan(&indexDef); err != nil {
			t.Fatalf("index %s not found: %v", indexName, err)
		}
		// Read from the definition the catalog renders, so the assertion
		// is about the index that exists rather than about migration text.
		for _, want := range []string{
			"host_id",
			"finished_at DESC NULLS LAST",
			"id DESC",
			"WHERE (status = 'completed'",
		} {
			if !strings.Contains(indexDef, want) {
				t.Errorf("index %s does not carry %q.\n  definition: %s\n"+
					"NULLS LAST is not decoration: DESC implies NULLS FIRST, so an index without "+
					"it does not match the view's ORDER BY and the planner adds a Sort.",
					indexName, want, indexDef)
			}
		}

		// A fleet, so a sequential scan over scan_runs would be a
		// different plan shape than a probe.
		user := seedUser(t, pool)
		var target uuid.UUID
		for i := 0; i < 40; i++ {
			h := seedHost(t, pool, user)
			if i == 0 {
				target = h
			}
			for j := 0; j < 5; j++ {
				run := seedRun(t, pool, h, "completed",
					hoursAgo(10+j), hoursAgo(10+j))
				if i == 0 && j == 0 {
					seedRuleState(t, pool, h, "rule-a", "pass", run)
				}
			}
		}
		if _, err := pool.Exec(ctx, `ANALYZE scan_runs`); err != nil {
			t.Fatalf("analyze: %v", err)
		}

		plan := explain(t, pool, `
			SELECT count(*) FROM host_rule_state_current WHERE host_id = $1`, target)

		if !strings.Contains(plan, indexName) {
			t.Errorf("the corpus lookup plan does not use %s:\n%s", indexName, plan)
		}
		// The Sort is the assertion. With the null ordering wrong the
		// plan still names the index above and still reads as healthy.
		if strings.Contains(plan, "Sort") {
			t.Errorf("the corpus lookup plan contains a Sort node:\n%s\n"+
				"The index exists to make this a probe. A Sort above the index scan means the "+
				"index's ordering does not match the view's ORDER BY, which is what a wrong "+
				"NULLS clause produces while leaving every other part of the plan looking right.", plan)
		}
		// Per-host, not fleet-wide.
		if strings.Contains(plan, "Seq Scan on scan_runs") {
			t.Errorf("the plan scans scan_runs sequentially:\n%s\nscan_runs grows one row per "+
				"host per scan forever, so a per-host read must not walk other hosts' runs", plan)
		}
	})
}

// explain returns the query plan as text.
func explain(t *testing.T, pool *pgxpool.Pool, query string, args ...any) string {
	t.Helper()
	rows, err := pool.Query(context.Background(), "EXPLAIN "+query, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan plan line: %v", err)
		}
		fmt.Fprintln(&b, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate plan: %v", err)
	}
	if b.Len() == 0 {
		t.Fatal("EXPLAIN returned no rows, so every plan assertion below would pass vacuously")
	}
	return b.String()
}

var _ = time.Now
