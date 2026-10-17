package secretkey

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func writeKey(t *testing.T, raw []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// ReadFile applies LoadFromFile's checks and leaves the active key alone.
func TestReadFile(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	raw := make([]byte, KeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	k, err := ReadFile(writeKey(t, raw, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.Material(), raw) {
		t.Error("ReadFile returned other material")
	}
	if _, err := Active(); err == nil {
		t.Error("ReadFile installed the key")
	}
	if _, err := ReadFile(writeKey(t, raw, 0o644)); err == nil {
		t.Error("a group- or world-readable key was accepted")
	}
	if _, err := ReadFile(writeKey(t, raw[:16], 0o600)); err == nil {
		t.Error("a short key was accepted")
	}
	if err := LoadFromFile(writeKey(t, raw, 0o600)); err != nil {
		t.Fatal(err)
	}
	if a, err := Active(); err != nil || !bytes.Equal(a.Material(), raw) {
		t.Errorf("LoadFromFile did not install the key: %v", err)
	}
}
