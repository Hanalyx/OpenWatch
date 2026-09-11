package report

// Generator for the worked example in docs/guides/REPORT_VERIFICATION.md.
//
// It is a GENERATOR, not a gate: it runs only when OPENWATCH_WRITE_REPORT_FIXTURE=1
// and a test database is configured, and it writes the artifact the published
// guide is verified against. The gate that runs everywhere is the verification
// test, which re-checks the committed artifact with the documented commands.
//
// The point of generating rather than hand-writing the fixture is that a
// hand-built example is self-consistent by construction: it proves the example
// agrees with itself, not that it agrees with what OpenWatch emits. This one
// comes out of Generate and Export, the same calls the API serves.
//
// Regenerate with:
//
//	OPENWATCH_TEST_DSN=... OPENWATCH_WRITE_REPORT_FIXTURE=1 \
//	  go test ./internal/report/ -run TestWriteVerificationFixture -count=1

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteVerificationFixture(t *testing.T) {
	if os.Getenv("OPENWATCH_WRITE_REPORT_FIXTURE") != "1" {
		t.Skip("generator; set OPENWATCH_WRITE_REPORT_FIXTURE=1 to rewrite the published example")
	}
	pool := freshPool(t)
	ctx := context.Background()

	// A DURABLE key, the production shape: a 32-byte raw Ed25519 seed. An
	// ephemeral key would sign an artifact nobody could ever re-verify.
	//
	// The seed is DETERMINISTIC and written here in the clear, so the private
	// key of the published example is derivable by anyone reading this file.
	// That is deliberate: the fixture is a teaching artifact, not evidence.
	// Never describe the committed key as secret or reuse it anywhere.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "report_signing.key")
	if err := os.WriteFile(keyPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(keyPath)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	svc := NewService(pool).WithSigner(signer)
	owner := seedUser(t, pool)
	h := seedHost(t, pool, owner, false)
	seedRuleState(t, pool, h, "sshd-disable-root-login", "pass", "high")
	seedRuleState(t, pool, h, "sshd-set-idle-timeout", "fail", "medium")

	rep, err := svc.Generate(ctx, "auditor@example.com", GenerateRequest{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	canonical, mediaType, err := svc.Export(ctx, rep.ID, "json")
	if err != nil {
		t.Fatalf("Export json: %v", err)
	}
	if mediaType != "application/json" {
		t.Fatalf("media type = %q", mediaType)
	}

	root := filepath.Join(repoRoot(t), "docs", "guides", "examples", "report-verification")
	writeTriplet(t, root, rep, canonical, signer)

	// The trust anchor an auditor is supposed to hold: the FULL SHA-256 of the
	// decoded public key. Written beside the fixture so the worked example can
	// be run end to end; in real use it arrives through a channel that does not
	// depend on the server serving the report.
	sum := sha256.Sum256(signer.PublicKey())
	if err := os.WriteFile(filepath.Join(root, "trusted-key.sha256"),
		[]byte(hex.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// ---- The counterexample: a DIFFERENT key signing DIFFERENT content, each
	// internally consistent. This is the artifact a server able to serve a
	// replacement would hand you. Consistency-only verification passes on it.
	// Only the trusted anchor tells it apart from the genuine one.
	seed2 := make([]byte, 32)
	for i := range seed2 {
		seed2[i] = byte(0xA0 + i)
	}
	keyPath2 := filepath.Join(dir, "other_signing.key")
	if err := os.WriteFile(keyPath2, seed2, 0o600); err != nil {
		t.Fatal(err)
	}
	signer2, err := NewSigner(keyPath2)
	if err != nil {
		t.Fatalf("NewSigner 2: %v", err)
	}
	if signer2.KeyID() == signer.KeyID() {
		t.Fatal("the two fixture keys collide; pick another seed")
	}
	h2 := seedHost(t, pool, owner, false)
	seedRuleState(t, pool, h2, "sshd-disable-root-login", "pass", "high")
	svc2 := NewService(pool).WithSigner(signer2)
	rep2, err := svc2.Generate(ctx, "attacker@example.com", GenerateRequest{})
	if err != nil {
		t.Fatalf("Generate 2: %v", err)
	}
	canonical2, _, err := svc2.Export(ctx, rep2.ID, "json")
	if err != nil {
		t.Fatalf("Export 2: %v", err)
	}
	sub := filepath.Join(root, "counterexample")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTriplet(t, sub, rep2, canonical2, signer2)
	t.Logf("wrote fixtures to %s and %s", root, sub)
}

// writeTriplet writes the three files an operator holds: the canonical JSON
// face, the report metadata, and the signing-key response.
func writeTriplet(t *testing.T, out string, rep Report, canonical []byte, signer *Signer) {
	t.Helper()
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(out, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// No trailing newline: this file's SHA-256 is its identity.
	write("report.json", canonical)

	// The fields an operator reads off GET /api/v1/reports/{id}.
	meta, _ := json.MarshalIndent(map[string]any{
		"id":             rep.ID.String(),
		"content_sha256": rep.ContentSHA256,
		"signature":      base64.StdEncoding.EncodeToString(rep.Signature),
		"signing_key_id": rep.SigningKeyID,
	}, "", "  ")
	write("report.meta.json", append(meta, '\n'))

	// The GET /api/v1/reports/signing-key response shape.
	key, _ := json.MarshalIndent(map[string]any{
		"key_id":     signer.KeyID(),
		"algorithm":  "ed25519",
		"public_key": base64.StdEncoding.EncodeToString(signer.PublicKey()),
		"ephemeral":  signer.Ephemeral(),
	}, "", "  ")
	write("signing-key.json", append(key, '\n'))
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(filepath.Dir(wd))
}
