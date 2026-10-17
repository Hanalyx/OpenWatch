// @spec system-credential-protection

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/credprotect/fingerprint"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/secretkey"
)

func keyFile(t *testing.T) string {
	t.Helper()
	raw := make([]byte, secretkey.KeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "credential.key")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// @ac AC-23
func TestCredentialKeyCommand(t *testing.T) {
	t.Run("system-credential-protection/AC-23", func(t *testing.T) {
		ctx := context.Background()
		pool := dbtest.Pool(t)
		for _, q := range []string{
			`TRUNCATE credprotect_restrictions, credprotect_submissions, credprotect_verification_requests,
			 credprotect_verified_secrets, credprotect_fingerprint_keys CASCADE`,
			`DELETE FROM credprotect_keyring`,
			`INSERT INTO credprotect_keyring (singleton) VALUES (true)`,
		} {
			if _, err := pool.Exec(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		oldFile, newFile := keyFile(t), keyFile(t)
		run := func(active string, args ...string) (int, string, string) {
			var out, errb bytes.Buffer
			code := runCredentialKey(ctx, pool, active, args, &out, &errb)
			return code, out.String(), errb.String()
		}

		// No keyring yet: reported apart, never as success.
		if code, out, _ := run(oldFile, "verify"); code != credentialKeyNotInitialized || !strings.Contains(out, "no keyring exists yet") {
			t.Fatalf("verify before initialization: %d %q", code, out)
		}
		if code, _, _ := run(newFile, "rewrap", "--previous-key-file", oldFile); code != credentialKeyNotInitialized {
			t.Fatalf("rewrap before initialization: %d", code)
		}

		old, err := secretkey.ReadFile(oldFile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fingerprint.Load(ctx, pool, old, time.Now()); err != nil {
			t.Fatal(err)
		}
		if code, out, errs := run(oldFile, "verify"); code != credentialKeyOK || !strings.Contains(out, "1 fingerprint key(s)") {
			t.Fatalf("verify: %d %q %q", code, out, errs)
		}

		// Usage.
		if code, _, errs := run(newFile, "rewrap"); code != credentialKeyUsage || !strings.Contains(errs, "--previous-key-file is required") {
			t.Errorf("rewrap without the previous key: %d %q", code, errs)
		}
		if code, _, _ := run(newFile, "verify", "extra"); code != credentialKeyUsage {
			t.Errorf("verify with an extra argument: %d", code)
		}

		// The rotation: re-wrap, retry, verify with the new key only.
		if code, out, errs := run(newFile, "rewrap", "--previous-key-file", oldFile); code != credentialKeyOK || !strings.Contains(out, "re-wrapped 1") {
			t.Fatalf("rewrap: %d %q %q", code, out, errs)
		}
		if code, out, _ := run(newFile, "rewrap", "--previous-key-file", oldFile); code != credentialKeyOK || !strings.Contains(out, "already re-wrapped") {
			t.Errorf("retry: %d %q", code, out)
		}
		if code, _, _ := run(newFile, "verify"); code != credentialKeyOK {
			t.Errorf("verify with the new key: %d", code)
		}
		// The old key no longer reads the keyring, and the failure points
		// to the re-wrap.
		if code, _, errs := run(oldFile, "verify"); code != credentialKeyFailed || !strings.Contains(errs, "credential-key rewrap") {
			t.Errorf("verify with the old key: %d %q", code, errs)
		}
		// A key file anyone can read is refused before anything runs.
		if err := os.Chmod(newFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if code, _, errs := run(newFile, "verify"); code != credentialKeyFailed || !strings.Contains(errs, "must be 0600") {
			t.Errorf("verify with a readable key file: %d %q", code, errs)
		}
	})
}
