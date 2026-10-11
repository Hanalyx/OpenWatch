// @spec release-packets
//
// The F1 readings (release/prep/packets/f1-readings.sh) query scan_runs,
// scan_results and audit_events on a release server. These tests run that
// script's own SQL, unchanged except for binding :'scan' as $1, against the
// migrated schema, so a migration that breaks a reading fails here and not on
// a fleet server. DB integration tests; skipped without OPENWATCH_TEST_DSN.
package scanruns

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var shellFunc = regexp.MustCompile(`^(\w+)\(\) \{$`)

// f1Queries maps each reading function in f1-readings.sh to its SQL.
func f1Queries(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "release", "prep", "packets", "f1-readings.sh"))
	if err != nil {
		t.Fatalf("read f1-readings.sh: %v", err)
	}
	// Each heredoc belongs to the shell function it sits in; a function
	// ends at a line that is exactly "}".
	out := map[string]string{}
	fn, inSQL := "", false
	var sql []string
	for _, l := range strings.Split(string(raw), "\n") {
		switch {
		case inSQL && l == "SQL":
			if fn == "" || out[fn] != "" {
				t.Fatalf("a SQL heredoc outside a function, or two in %q", fn)
			}
			out[fn] = strings.ReplaceAll(strings.Join(sql, "\n"), ":'scan'", "$1")
			inSQL, sql = false, nil
		case inSQL:
			// psql meta-commands (\pset) are not SQL. Not a raw string: Specter's
			// scanner reads a backslash before a backtick as an escape, and the
			// rest of the file, annotations included, vanishes from coverage.
			if !strings.HasPrefix(strings.TrimSpace(l), "\\") {
				sql = append(sql, l)
			}
		case strings.Contains(l, "<<'SQL'"):
			inSQL = true
		case shellFunc.MatchString(l):
			fn = shellFunc.FindStringSubmatch(l)[1]
		case l == "}":
			fn = ""
		}
	}
	if inSQL {
		t.Fatalf("an unterminated SQL heredoc in %q", fn)
	}
	for _, name := range []string{"scan_run", "result_counts", "skip_reasons", "audit_trail", "consistent"} {
		if out[name] == "" {
			t.Fatalf("f1-readings.sh has no SQL for %s; found %v", name, keys(out))
		}
	}
	return out
}

func keys(m map[string]string) []string {
	var k []string
	for name := range m {
		k = append(k, name)
	}
	return k
}

func rows(t *testing.T, pool *pgxpool.Pool, sql string, scan string) [][]string {
	t.Helper()
	rs, err := pool.Query(context.Background(), sql, scan)
	if err != nil {
		t.Fatalf("query: %v\n%s", err, sql)
	}
	defer rs.Close()
	var out [][]string
	for rs.Next() {
		vals, err := rs.Values()
		if err != nil {
			t.Fatalf("values: %v", err)
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			row[i] = fmt.Sprint(v)
		}
		out = append(out, row)
	}
	if err := rs.Err(); err != nil {
		t.Fatalf("rows: %v\n%s", err, sql)
	}
	return out
}

type scanFixture struct {
	pool              *pgxpool.Pool
	scan, host, other uuid.UUID
	corr              string
}

// seedScan writes one completed scan with three results and its real audit
// trail, plus the noise a time-window join would pick up: another scan's
// events on the same host in the same minutes, and an event carrying this
// scan's correlation id for a different host.
func seedScan(t *testing.T) scanFixture {
	t.Helper()
	pool := freshPool(t)
	ctx := context.Background()
	user := seedUser(t, pool)
	host := seedHost(t, pool, user)
	other := seedHost(t, pool, user)
	scan, _ := uuid.NewV7()
	corr := "req-" + scan.String()
	at := time.Now().UTC().Add(-time.Hour)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, sql)
		}
	}
	exec(`INSERT INTO scan_runs (id, host_id, trigger_source, requested_by, status, queued_at,
	        started_at, finished_at, rules_pass, rules_fail, rules_skipped, rules_error,
	        engine_version, correlation_id)
	      VALUES ($1, $2, 'on_demand', $3, 'completed', $4, $5, $6, 1, 1, 1, 0, 'v0.10.0', $7)`,
		scan, host, user, at, at.Add(time.Second), at.Add(40*time.Second), corr)
	for _, r := range [][]string{{"r-pass", "pass", ""}, {"r-fail", "fail", ""},
		{"r-skip", "skipped", "not applicable: host RHEL 9.8, rule targets ubuntu >=22"}} {
		var reason any
		if r[2] != "" {
			reason = r[2]
		}
		exec(`INSERT INTO scan_results (scan_id, host_id, rule_id, status, skip_reason)
		      VALUES ($1, $2, $3, $4, $5)`, scan, host, r[0], r[1], reason)
	}
	event := func(action, actorType, corrID string, detail map[string]string, when time.Time) {
		t.Helper()
		id, _ := uuid.NewV7()
		d, _ := json.Marshal(detail)
		exec(`INSERT INTO audit_events (id, correlation_id, actor_type, actor_id, action, detail,
		        occurred_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			id, corrID, actorType, map[bool]any{true: user.String(), false: nil}[actorType == "user"],
			action, d, when)
	}
	event("scan.queued", "user", corr, map[string]string{"scan_id": scan.String(),
		"host_id": host.String()}, at)
	event("scan.started", "system", corr, map[string]string{"host_id": host.String()},
		at.Add(time.Second))
	event("scan.completed", "system", corr, map[string]string{"host_id": host.String()},
		at.Add(40*time.Second))
	// Noise: another scan on the same host, inside the same window.
	otherScan, _ := uuid.NewV7()
	event("scan.queued", "user", "req-noise", map[string]string{"scan_id": otherScan.String(),
		"host_id": host.String()}, at.Add(10*time.Second))
	event("scan.completed", "system", "req-noise", map[string]string{"host_id": host.String()},
		at.Add(30*time.Second))
	// Noise: this correlation id on another host.
	event("scan.completed", "system", corr, map[string]string{"host_id": other.String()},
		at.Add(20*time.Second))
	return scanFixture{pool: pool, scan: scan, host: host, other: other, corr: corr}
}

func consistency(t *testing.T, f scanFixture, q map[string]string, scan string) string {
	t.Helper()
	got := rows(t, f.pool, q["consistent"], scan)
	if len(got) != 1 || len(got[0]) != 1 {
		t.Fatalf("consistency returned %v", got)
	}
	return got[0][0]
}

// @ac AC-06
// AC-06: the F1 readings' SQL, run against the migrated schema, reads one
// scan by id and binds its audit trail by scan id and correlation id.
func TestReleaseReadings_F1SQLReadsOneScanByID(t *testing.T) {
	t.Run("release-packets/AC-06", func(t *testing.T) {
		q := f1Queries(t)
		f := seedScan(t)
		run := rows(t, f.pool, q["scan_run"], f.scan.String())
		if len(run) != 1 || run[0][0] != f.scan.String() || run[0][4] != "completed" {
			t.Fatalf("scan run: %v", run)
		}
		counts := rows(t, f.pool, q["result_counts"], f.scan.String())
		if fmt.Sprint(counts) != "[[fail 1] [pass 1] [skipped 1]]" {
			t.Fatalf("result counts: %v", counts)
		}
		skips := rows(t, f.pool, q["skip_reasons"], f.scan.String())
		if len(skips) != 1 || skips[0][0] != "1" || !strings.Contains(skips[0][1], "ubuntu >=22") {
			t.Fatalf("skip reasons: %v", skips)
		}
		trail := rows(t, f.pool, q["audit_trail"], f.scan.String())
		var actions []string
		for _, r := range trail {
			actions = append(actions, r[1])
			if r[5] != f.corr {
				t.Errorf("an event from another correlation was bound: %v", r)
			}
		}
		if strings.Join(actions, ",") != "scan.queued,scan.started,scan.completed" {
			t.Fatalf("audit trail is %v; want exactly this scan's three events, without the "+
				"other scan's or the other host's", actions)
		}
		if got := consistency(t, f, q, f.scan.String()); got != "consistent" {
			t.Fatalf("consistency: %q", got)
		}
	})
}

// @ac AC-06
// AC-06: the consistency reading fails, naming why, for each inconsistent scan.
func TestReleaseReadings_F1ConsistencyNamesEachFault(t *testing.T) {
	t.Run("release-packets/AC-06", func(t *testing.T) {
		q := f1Queries(t)
		cases := []struct {
			name  string
			setup func(f scanFixture) string
			want  string
		}{
			{"no such scan", func(f scanFixture) string {
				id, _ := uuid.NewV7()
				return id.String()
			}, "no such scan"},
			{"still running", func(f scanFixture) string {
				f.exec(t, `UPDATE scan_runs SET status = 'running' WHERE id = $1`, f.scan)
				return f.scan.String()
			}, "scan is running"},
			{"counts differ", func(f scanFixture) string {
				f.exec(t, `UPDATE scan_runs SET rules_pass = 2 WHERE id = $1`, f.scan)
				return f.scan.String()
			}, "run counts differ from result rows"},
			{"no result rows", func(f scanFixture) string {
				f.exec(t, `DELETE FROM scan_results WHERE scan_id = $1`, f.scan)
				return f.scan.String()
			}, "no result rows"},
			{"a failed event", func(f scanFixture) string {
				id, _ := uuid.NewV7()
				f.exec(t, `INSERT INTO audit_events (id, correlation_id, actor_type, action, detail)
				           VALUES ($1, $2, 'system', 'scan.failed', $3)`,
					id, f.corr, fmt.Sprintf(`{"host_id":%q}`, f.host.String()))
				return f.scan.String()
			}, "scan.failed events: 1"},
			{"no completed event", func(f scanFixture) string {
				f.exec(t, `UPDATE scan_runs SET correlation_id = 'req-elsewhere' WHERE id = $1`, f.scan)
				return f.scan.String()
			}, "scan.completed events: 0"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				f := seedScan(t)
				scan := c.setup(f)
				if got := consistency(t, f, q, scan); got != c.want {
					t.Fatalf("consistency: %q, want %q", got, c.want)
				}
			})
		}
	})
}

func (f scanFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec: %v\n%s", err, sql)
	}
}
