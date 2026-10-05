// Operator commands in the tracked Markdown that must survive a copy and
// paste (CP bugs/OW-105, B7 and B8).
//
// B8: GET /api/v1/system/{intelligence,discovery,scan}/config returns
// {config, defaults}, and PUT takes the bare config object. A jq filter that
// sets maintenance_global on the GET response sends the wrapper back and is
// refused; one that reads .maintenance_global prints null.
//
// B7: the real DSN lives only in /etc/openwatch/secrets.env, which the unit
// loads with EnvironmentFile=. A command run with `sudo -u openwatch` does not
// inherit it, so check-config shows the TOML dsn and migrate connects with the
// wrong credentials unless the same command loads the file.
package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// trackedMarkdown returns the repo-relative paths of every tracked .md file,
// leaving out vendored trees and the archived Python-era docs.
func trackedMarkdown(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", repoRootForLinks(t), "ls-files", "*.md").Output()
	if err != nil {
		t.Skipf("git ls-files unavailable (%v); skipping", err)
	}
	var files []string
	for _, rel := range strings.Fields(string(out)) {
		if strings.Contains(rel, "node_modules/") || strings.HasPrefix(rel, "docs/_history/") {
			continue
		}
		files = append(files, rel)
	}
	if len(files) == 0 {
		t.Fatal("git ls-files listed no Markdown files")
	}
	return files
}

func readTracked(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRootForLinks(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// docCommand is one shell command as a reader would copy it: a fenced line
// joined with its continuation lines, or one inline code span.
type docCommand struct {
	line int // 1-based line where the command starts
	text string
}

var (
	fenceLine  = regexp.MustCompile("^\\s*```")
	inlineSpan = regexp.MustCompile("`([^`]+)`")
)

// docCommands splits a Markdown document into commands. Inside a fence, a line
// that ends with a backslash or leaves a single quote open continues onto the
// next line, which is how the secrets.env wrapper spans two lines. Outside a
// fence, each paragraph is joined first so an inline span may wrap.
func docCommands(doc string) []docCommand {
	var cmds []docCommand
	lines := strings.Split(doc, "\n")
	inFence := false
	var cur []string
	start := 0
	flush := func() {
		if len(cur) > 0 {
			cmds = append(cmds, docCommand{line: start, text: strings.Join(cur, "\n")})
			cur = nil
		}
	}
	var para []string
	paraStart := 0
	flushPara := func() {
		if len(para) > 0 {
			for _, m := range inlineSpan.FindAllStringSubmatch(strings.Join(para, " "), -1) {
				cmds = append(cmds, docCommand{line: paraStart, text: m[1]})
			}
			para = nil
		}
	}
	for i, ln := range lines {
		if fenceLine.MatchString(ln) {
			flush()
			flushPara()
			inFence = !inFence
			continue
		}
		if inFence {
			if len(cur) == 0 {
				start = i + 1
			}
			cur = append(cur, ln)
			joined := strings.Join(cur, "\n")
			if strings.Count(joined, "'")%2 == 0 && !strings.HasSuffix(strings.TrimRight(ln, " "), "\\") {
				flush()
			}
			continue
		}
		if strings.TrimSpace(ln) == "" {
			flushPara()
			continue
		}
		if len(para) == 0 {
			paraStart = i + 1
		}
		para = append(para, ln)
	}
	flush()
	flushPara()
	return cmds
}

// jqFilter captures the filter of a jq invocation, quoted or bare.
var jqFilter = regexp.MustCompile(`\bjq\s+(?:-\S+\s+)*(?:'([^']*)'|"([^"]*)"|(\.\S*))`)

// onConfig accepts `.config | .maintenance_global ...` and
// `.config.maintenance_global`.
var onConfig = regexp.MustCompile(`\.config\s*(\||\.maintenance_global)`)

// maintenanceFilters returns the jq filters in doc that mention
// maintenance_global and do not operate on .config.
func maintenanceFilters(doc string) (found int, bad []string) {
	for i, ln := range strings.Split(doc, "\n") {
		if !strings.Contains(ln, "maintenance_global") {
			continue
		}
		for _, m := range jqFilter.FindAllStringSubmatch(ln, -1) {
			f := m[1] + m[2] + m[3]
			if !strings.Contains(f, "maintenance_global") {
				continue
			}
			found++
			if !onConfig.MatchString(f) {
				bad = append(bad, strings.TrimSpace(ln)+"  (line "+strconv.Itoa(i+1)+")")
			}
		}
	}
	return found, bad
}

func TestMaintenanceRunbook_JqOperatesOnConfig(t *testing.T) {
	t.Run("the scanner rejects the wrapper round-trip", func(t *testing.T) {
		old := "  | jq '.maintenance_global = true' \\\n" +
			"curl -sk https://localhost:8443/api/v1/system/intelligence/config | jq .maintenance_global\n"
		if n, bad := maintenanceFilters(old); n != 2 || len(bad) != 2 {
			t.Fatalf("old form: found %d, flagged %d; want 2 and 2", n, len(bad))
		}
		good := "  | jq '.config | .maintenance_global = true' \\\n" +
			"curl -sk https://localhost:8443/api/v1/system/intelligence/config | jq .config.maintenance_global\n"
		if n, bad := maintenanceFilters(good); n != 2 || len(bad) != 0 {
			t.Fatalf("fixed form: found %d, flagged %v; want 2 and none", n, bad)
		}
	})

	t.Run("tracked docs unwrap .config", func(t *testing.T) {
		total := 0
		for _, rel := range trackedMarkdown(t) {
			n, bad := maintenanceFilters(readTracked(t, rel))
			total += n
			for _, b := range bad {
				t.Errorf("%s: jq filter on maintenance_global ignores the {config, defaults} wrapper: %s", rel, b)
			}
		}
		// The runbooks carry this round-trip today. Finding none means the
		// scanner went blind, not that the docs are clean.
		if total == 0 {
			t.Fatal("no jq filter on maintenance_global found in any tracked doc")
		}
		t.Logf("checked %d jq filters on maintenance_global", total)
	})
}

// serviceUserDBCommand matches a command run as the service user that reads
// the database DSN: an openwatch subcommand or psql against the DSN variable.
var serviceUserDBCommand = regexp.MustCompile(
	`sudo\s+-u\s+openwatch\b[\s\S]*(\bopenwatch\b[^|;&\n]*\b(check-config|migrate|create-admin)\b|psql\s+"\$OPENWATCH_DATABASE_DSN")`)

const loadsSecrets = ". /etc/openwatch/secrets.env"

// secretsExempt names files another change owns. Each entry says why.
var secretsExempt = map[string]string{
	// P2b (CP bugs/OW-105) corrects this runbook's DSN handling; it holds no
	// `sudo -u openwatch` command today, so this exempts nothing yet.
	"docs/runbooks/DATABASE_MIGRATIONS.md": "owned by the P2b change",
}

func unwrappedServiceUserCommands(doc string) (found int, bad []docCommand) {
	for _, c := range docCommands(doc) {
		if !serviceUserDBCommand.MatchString(c.text) {
			continue
		}
		found++
		if !strings.Contains(c.text, loadsSecrets) {
			bad = append(bad, c)
		}
	}
	return found, bad
}

func TestSecretsEnvRunbook_ServiceUserCommandsLoadSecrets(t *testing.T) {
	t.Run("the scanner rejects a bare service-user command", func(t *testing.T) {
		doc := "```bash\n" +
			"sudo -u openwatch /usr/bin/openwatch --config /etc/openwatch/openwatch.toml check-config\n" +
			"sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a;\n" +
			"  /usr/bin/openwatch --config /etc/openwatch/openwatch.toml migrate'\n" +
			"```\n\n" +
			"Run `sudo -u openwatch openwatch migrate --status` first.\n"
		n, bad := unwrappedServiceUserCommands(doc)
		if n != 3 || len(bad) != 2 {
			t.Fatalf("found %d, flagged %d; want 3 and 2 (%v)", n, len(bad), bad)
		}
	})

	t.Run("tracked docs load secrets.env in the same command", func(t *testing.T) {
		total := 0
		for _, rel := range trackedMarkdown(t) {
			if _, ok := secretsExempt[rel]; ok {
				continue
			}
			n, bad := unwrappedServiceUserCommands(readTracked(t, rel))
			total += n
			for _, c := range bad {
				t.Errorf("%s:%d: runs as the openwatch user without loading secrets.env, "+
					"so it sees the TOML dsn rather than the service's: %s", rel, c.line, c.text)
			}
		}
		if total == 0 {
			t.Fatal("no `sudo -u openwatch` database command found in any tracked doc")
		}
		t.Logf("checked %d service-user database commands", total)
	})
}
