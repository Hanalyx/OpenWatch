package identity

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// FileBreachCorpus is a HaveIBeenPwned-format breach corpus loaded from
// disk. The file format is one entry per line:
//
//	<SHA1-suffix>:<count>
//
// where the leading 5 chars of the SHA-1 are the "prefix" (used by the
// HIBP API for k-anonymity). For a flat-file local corpus we just store
// the full 40-char SHA-1 followed by ":<count>"; lookups are O(1) via a
// pre-built map.
//
// Production deploys the full corpus (~700M passwords ≈ 30 GB). Tests
// use a small fixture in testdata/.
//
// Spec system-auth-identity AC-02, C-02.
type FileBreachCorpus struct {
	mu    sync.RWMutex
	known map[string]struct{}
}

// LoadFileBreachCorpus reads the corpus file. Empty lines and comments
// (lines starting with #) are skipped. Returns a usable corpus even if
// path doesn't exist — production callers should fail closed (caller's
// responsibility to check).
func LoadFileBreachCorpus(path string) (*FileBreachCorpus, error) {
	c := &FileBreachCorpus{known: make(map[string]struct{})}
	f, err := os.Open(path) //nolint:gosec // path is operator-supplied via OPENWATCH_BREACH_CORPUS_FILE
	if err != nil {
		return nil, fmt.Errorf("identity: open breach corpus %q: %w", path, err)
	}
	defer f.Close()
	if err := c.load(f); err != nil {
		return nil, err
	}
	return c, nil
}

// NewMemoryBreachCorpus is a tiny in-memory corpus useful for tests
// and for environments where the operator chooses to ship a curated
// subset (top-N most common passwords) rather than the full HIBP dump.
//
// The input is the plaintext passwords; the constructor SHA-1's them
// once at load time.
func NewMemoryBreachCorpus(plain []string) *FileBreachCorpus {
	c := &FileBreachCorpus{known: make(map[string]struct{}, len(plain))}
	for _, p := range plain {
		c.known[sha1Hex(p)] = struct{}{}
	}
	return c
}

func (c *FileBreachCorpus) load(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	// Tolerate long lines (real HIBP rows are short, but we accept up to 1 MiB to be safe).
	const maxLine = 1 << 20
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, maxLine)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "<sha1-hex>:<count>" or "<sha1-hex>"
		hash := line
		if i := strings.Index(line, ":"); i > 0 {
			hash = line[:i]
		}
		hash = strings.ToUpper(hash)
		if len(hash) != 40 {
			return fmt.Errorf("identity: breach corpus row has %d-char hash, want 40", len(hash))
		}
		c.known[hash] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("identity: read breach corpus: %w", err)
	}
	return nil
}

// Contains hashes pw with SHA-1 and reports whether the hash is in the
// corpus. Lookup is O(1).
//
// Spec C-02, AC-02.
func (c *FileBreachCorpus) Contains(pw string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.known == nil {
		return false, errors.New("identity: breach corpus not initialized")
	}
	_, ok := c.known[sha1Hex(pw)]
	return ok, nil
}

// Size returns the number of distinct compromised hashes loaded.
// Diagnostics only; admins use this in /admin/health to confirm the
// corpus is the intended one.
func (c *FileBreachCorpus) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.known)
}
