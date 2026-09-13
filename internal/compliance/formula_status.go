package compliance

// FormulaStatus says which scoring formula produced the rows behind an
// aggregate, so a null score is never an unexplained null.
//
// A boolean "mixed" flag cannot carry this. Under it a legacy-only day and a
// version-2 day both read false with a score, and the two are different claims:
// one is comparable with today's numbers and the other is not. Three states need
// three values.
//
// Ratified 2026-09-03. A day holding more than one formula version reports NO
// score, keeps its participation and outcome counts, and says mixed. It never
// picks one version, never averages incompatible values, and never drops
// contributors. Publishing one line per version was rejected because two lines
// on one chart imply a comparison that is not valid; scoring only the version-2
// rows was rejected because it silently changes the population.
type FormulaStatus string

const (
	// FormulaIdentified: every contributing row was produced by formula 2. The
	// score means passing over passing plus failing and is comparable with any
	// other identified point.
	FormulaIdentified FormulaStatus = "identified"

	// FormulaLegacyUnknown: every contributing row predates the redesign. Its
	// stored score is preserved as it stands. The arithmetic behind it is
	// knowable, but the corpus it measured against is not, so it is NOT
	// comparable with an identified point on the same axis.
	FormulaLegacyUnknown FormulaStatus = "legacy_unknown"

	// FormulaMixed: contributing rows carry more than one formula version.
	// There is no score, because the versions measure different things.
	FormulaMixed FormulaStatus = "mixed"
)

// Valid reports whether s is one of the three states.
func (s FormulaStatus) Valid() bool {
	switch s {
	case FormulaIdentified, FormulaLegacyUnknown, FormulaMixed:
		return true
	}
	return false
}

// FormulaStatusSQL builds the expression that classifies an aggregate's rows.
//
// versionCol is the nullable formula_version column. NULL means "written before
// the redesign", which COALESCE maps to 0 so it counts as its own version
// rather than disappearing from the DISTINCT.
func FormulaStatusSQL(versionCol string) string {
	v := `COALESCE(` + versionCol + `, 0)`
	return `CASE WHEN COUNT(DISTINCT ` + v + `) > 1 THEN 'mixed'
	             WHEN MIN(` + v + `) = 2 THEN 'identified'
	             ELSE 'legacy_unknown' END`
}
