// @spec system-credential-protection

package packaging_test

import (
	"strings"
	"testing"
)

// @ac AC-24
// AC-24: the DEK rotation keeps credential protection readable. The new key
// is backed up before anything depends on it, the fingerprint keys are
// re-wrapped before the restart, verify runs before the old key is
// deleted, and the rollback reverses the re-wrap.
func TestSecretRotation_DEKRewrapsTheFingerprintKeys(t *testing.T) {
	t.Run("system-credential-protection/AC-24", func(t *testing.T) {
		doc := readAppFile(t, "docs/runbooks/SECRET_ROTATION.md")
		sec := secRunbookSection(t, doc, "## Rotate the credential DEK")
		at := func(s string) int {
			t.Helper()
			i := strings.Index(sec, s)
			if i < 0 {
				t.Fatalf("the DEK section does not contain %q", s)
			}
			return i
		}
		backup := at(`/root/credential.key.post-rotation`)
		envLine := at(`OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE=$NEW_DEK`)
		rewrap := at(`openwatch credential-key rewrap --previous-key-file /etc/openwatch/keys/credential.key`)
		restart := at(`Then restart and verify with the first block`)
		verify := at(`openwatch credential-key verify`)
		rollback := at(`6. Rollback is clean only`)
		reverse := at(`openwatch credential-key rewrap --previous-key-file '$NEW_DEK'`)
		deleteOld := at(`Then delete the old key file and the root-only copy`)
		for _, c := range []struct {
			before, after int
			what          string
		}{
			{backup, rewrap, "the new key is backed up before the re-wrap depends on it"},
			{envLine, rewrap, "the service points at the new key before the re-wrap reads it"},
			{rewrap, restart, "the re-wrap runs before the restart"},
			{restart, verify, "verify runs after the restart"},
			{rollback, reverse, "the rollback reverses the re-wrap"},
			{reverse, deleteOld, "the reverse re-wrap comes before the old key is deleted"},
		} {
			if c.before >= c.after {
				t.Errorf("out of order: %s", c.what)
			}
		}
		// Verify again before the old key goes, and read the exit codes.
		step7 := sec[strings.Index(sec, "7. Only after every secret is re-entered"):]
		if v, d := strings.Index(step7, "credential-key verify"), strings.Index(step7, "delete the old key file"); v < 0 || v > d {
			t.Error("step 7 does not verify before the old key is deleted")
		}
		for _, want := range []string{"Exit 0 means", "Exit 3 means", "do not\n   restart"} {
			if !strings.Contains(sec, want) {
				t.Errorf("the re-wrap's exit codes are not explained: missing %q", want)
			}
		}
		ref := readAppFile(t, "docs/guides/ENVIRONMENT_REFERENCE.md")
		if !strings.Contains(ref, "| `credential-key` |") {
			t.Error("the CLI reference does not list credential-key")
		}
	})
}
