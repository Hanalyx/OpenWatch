package identity

import (
	"strings"

	_ "embed"
)

// EnvBreachCorpusFile names the optional operator-supplied breach-corpus
// file (HIBP "<sha1>:<count>" rows) loaded via LoadFileBreachCorpus. When
// unwired/unset the embedded baseline below is used, so air-gapped installs
// work with no external file. (Wiring the override into the server boot path
// is a documented follow-up.)
const EnvBreachCorpusFile = "OPENWATCH_BREACH_CORPUS_FILE"

//go:embed common_passwords.txt
var defaultCorpusData string

// DefaultBreachCorpus returns the always-on embedded baseline corpus (the
// most common compromised passwords). Never nil — production password
// validation MUST run the breach check, not silently skip it as it did when
// the users service was wired with a nil corpus.
func DefaultBreachCorpus() *FileBreachCorpus {
	var plain []string
	for _, line := range strings.Split(defaultCorpusData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		plain = append(plain, line)
	}
	return NewMemoryBreachCorpus(plain)
}
