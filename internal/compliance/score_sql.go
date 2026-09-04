// SQL form of the formula.
//
// This file holds no database import and no query. It builds strings, which is
// why it can live beside the Go implementation without violating C-13's rule
// that the scoring package stays free of a database. Keeping the two forms in
// one package is the point: C-14 requires them to agree, and they cannot drift
// apart unnoticed when they sit next to each other and one test runs both.

package compliance

// ScoreSQL builds THE SQL score expression from a passing-count expression and
// an evaluated-count expression.
//
// It exists so every query layer and the conformance test run the same arithmetic
// rather than two copies that agree until one is edited. What varies between
// callers is how the counts are obtained; the rounding, the numeric cast and the
// NULLIF that turns "no verdict" into NULL are fixed here.
//
// NULLIF is what makes an unassessable host store NULL instead of 0: division
// by NULL is NULL in SQL, so absence falls out of the arithmetic.
//
// The cast to numeric is load-bearing. In float8 the on-boundary fixtures round
// the wrong way, and system-compliance-scoring C-14 requires this to agree with
// compliance.HostScore exactly, not within a tolerance. PostgreSQL ROUND on
// numeric is half away from zero, which is what compliance.Round1 implements.
func ScoreSQL(passing, evaluated string) string {
	return `ROUND(` + ScorePctSQL(passing, evaluated) + ` * 10) / 10`
}

// ScorePctSQL is the same percentage WITHOUT the final rounding, as exact
// numeric.
//
// Aggregates MUST average this, never ScoreSQL. Rounding each host to one
// decimal and then averaging is a different function from averaging and
// rounding once. The error has no fixed direction: each host's rounding moves
// its value either way, so the aggregate can land high or low depending on the
// fleet. Two hosts at 0/1 and 2/3 average to 33.333, which rounds to 33.3;
// rounding them first gives the mean of 0.0 and 66.7, which is 33.35 and rounds
// UP to 33.4. A fleet whose roundings mostly went down would drift the other
// way. That it cannot be predicted is the reason to remove it rather than
// budget for it.
//
// The type matters as much as the timing. numeric is exact and its division is
// carried to a defined scale, so the same inputs give the same answer on every
// server; float8 would reintroduce the representation error that made the REAL
// score_pct column disagree with Go.
func ScorePctSQL(passing, evaluated string) string {
	return `((` + passing + `)::numeric / NULLIF(` + evaluated + `, 0) * 100)`
}

// MeanScoreSQL averages already-computed per-host percentages and rounds ONCE.
//
// Pass it an expression naming a column of ScorePctSQL values, one row per host.
// It exists so no caller has to remember which of the two expressions to average:
// there is one way to aggregate, and it is this.
func MeanScoreSQL(hostPct string) string {
	return `ROUND(AVG(` + hostPct + `) * 10) / 10`
}

// StatusCountSQL is the count of rows in one status set, for ScoreSQL.
func StatusCountSQL(alias string, statuses string) string {
	return `COUNT(*) FILTER (WHERE ` + alias + `.current_status IN (` + statuses + `))`
}
