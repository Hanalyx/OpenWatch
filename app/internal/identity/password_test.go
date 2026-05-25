// @spec system-auth-identity
//
// Password hashing + validation tests covering ACs 01-05 and 19. The
// remaining auth-identity ACs (sessions, JWT, MFA) land in their own
// test files alongside their implementations.

package identity

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/internalrace"
)

// @ac AC-01
// AC-01: HashPassword returns an Argon2id PHC string; VerifyPassword
// round-trips the original and rejects any other input.
func TestPassword_HashAndVerify(t *testing.T) {
	t.Run("system-auth-identity/AC-01", func(t *testing.T) {
		hash, err := HashPassword("correct horse battery staple")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=1$") {
			t.Errorf("hash prefix wrong: %q", hash[:min(len(hash), 40)])
		}
		if err := VerifyPassword("correct horse battery staple", hash); err != nil {
			t.Errorf("verify same: %v", err)
		}
		if err := VerifyPassword("wrong horse battery staple", hash); err == nil {
			t.Error("verify different: expected error, got nil")
		}
		if err := VerifyPassword("", hash); err == nil {
			t.Error("verify empty: expected error, got nil")
		}
	})
}

// @ac AC-02
// AC-02: ValidatePassword rejects a password whose SHA-1 prefix appears
// in the local breach corpus; error is ErrPasswordBreached.
func TestPassword_BreachCorpusRejects(t *testing.T) {
	t.Run("system-auth-identity/AC-02", func(t *testing.T) {
		corpus := NewMemoryBreachCorpus([]string{
			"password",
			"123456789",
			"qwerty1234",
			"changeme",
		})
		err := ValidatePassword("password", DefaultPolicy(), corpus)
		if !errors.Is(err, ErrPasswordBreached) {
			t.Errorf("err = %v, want ErrPasswordBreached", err)
		}
		// A novel password of sufficient length passes.
		err = ValidatePassword("zXp9!q wHrgZ", DefaultPolicy(), corpus)
		if err != nil {
			t.Errorf("novel password rejected: %v", err)
		}
	})
}

// @ac AC-03
// AC-03: default policy accepts 8 chars; rejects 7 (too short) and
// 129 (too long).
func TestPassword_DefaultLengthBoundaries(t *testing.T) {
	t.Run("system-auth-identity/AC-03", func(t *testing.T) {
		p := DefaultPolicy()
		// Empty corpus so length is the only signal.
		corpus := NewMemoryBreachCorpus(nil)
		if err := ValidatePassword(strings.Repeat("a", 8), p, corpus); err != nil {
			t.Errorf("8-char rejected: %v", err)
		}
		if err := ValidatePassword(strings.Repeat("a", 7), p, corpus); !errors.Is(err, ErrPasswordTooShort) {
			t.Errorf("7-char err = %v, want ErrPasswordTooShort", err)
		}
		if err := ValidatePassword(strings.Repeat("a", 129), p, corpus); !errors.Is(err, ErrPasswordTooLong) {
			t.Errorf("129-char err = %v, want ErrPasswordTooLong", err)
		}
		// 128 (the boundary) accepted.
		if err := ValidatePassword(strings.Repeat("a", 128), p, corpus); err != nil {
			t.Errorf("128-char rejected: %v", err)
		}
	})
}

// @ac AC-04
// AC-04: admin policy rejects 14 chars; accepts 15.
func TestPassword_AdminLengthBoundaries(t *testing.T) {
	t.Run("system-auth-identity/AC-04", func(t *testing.T) {
		p := AdminPolicy()
		corpus := NewMemoryBreachCorpus(nil)
		if err := ValidatePassword(strings.Repeat("a", 14), p, corpus); !errors.Is(err, ErrPasswordTooShort) {
			t.Errorf("14-char err = %v, want ErrPasswordTooShort", err)
		}
		if err := ValidatePassword(strings.Repeat("a", 15), p, corpus); err != nil {
			t.Errorf("15-char rejected: %v", err)
		}
	})
}

// @ac AC-05
// AC-05: NIST 800-63B explicitly rejects character-class rules. A
// long all-lowercase password and a long all-digits password MUST be
// accepted on length/breach grounds (assuming they're not breached).
func TestPassword_NoCharacterClassEnforcement(t *testing.T) {
	t.Run("system-auth-identity/AC-05", func(t *testing.T) {
		// Use an empty breach corpus so we're testing only the policy logic.
		corpus := NewMemoryBreachCorpus(nil)
		// All-lowercase, all-digits passphrases — both accepted by spec C-03.
		// Picked 14-char strings that are unlikely to be in any real breach
		// corpus (would fail AC-02 if they were).
		for _, pw := range []string{
			"alllowercasekgs",
			"123450000xyzabc",
			"thequickbrownfx",
		} {
			if err := ValidatePassword(pw, DefaultPolicy(), corpus); err != nil {
				t.Errorf("password %q rejected: %v (NIST 800-63B prohibits character-class rules)", pw, err)
			}
		}
	})
}

// @ac AC-19
// AC-19: VerifyPassword p99 < 200ms over 50 calls. Spec target ensures
// the Argon2id parameters are not relaxed accidentally. Race-detector
// multiplier applied so the test passes under -race.
func TestPassword_VerifyLatency(t *testing.T) {
	t.Run("system-auth-identity/AC-19", func(t *testing.T) {
		hash, err := HashPassword("benchmark-baseline-password-x")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		const n = 50
		durs := make([]time.Duration, n)
		for i := 0; i < n; i++ {
			start := time.Now()
			_ = VerifyPassword("benchmark-baseline-password-x", hash)
			durs[i] = time.Since(start)
		}
		// Insertion sort + p99 pick.
		for i := 1; i < n; i++ {
			v := durs[i]
			j := i - 1
			for j >= 0 && durs[j] > v {
				durs[j+1] = durs[j]
				j--
			}
			durs[j+1] = v
		}
		nn := n
		idx := int(float64(nn) * 0.99)
		p99 := durs[idx]
		budget := 200 * time.Millisecond * time.Duration(internalrace.Multiplier())
		if p99 > budget {
			t.Errorf("VerifyPassword p99 = %v, want < %v (spec target 200ms)", p99, budget)
		}
		t.Logf("VerifyPassword p99 = %v over %d calls (budget %v)", p99, n, budget)
	})
}

// Companion: parsePHC rejects malformed input without panicking. Not an
// AC but exercises the error paths so the verify code stays safe under
// corrupted DB rows.
func TestPassword_ParsePHCInvalid(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-a-phc",
		"$argon2id$wrong",
		"$argon2id$v=99$m=65536,t=3,p=1$abc$def",  // wrong version
		"$argon2i$v=19$m=65536,t=3,p=1$abc$def",   // wrong algorithm
		"$argon2id$v=19$m=65536,t=3$abc$def",      // missing param
		"$argon2id$v=19$m=65536,t=3,p=1$@@@$def",  // invalid base64 salt
		"$argon2id$v=19$m=65536,t=3,p=1$YWJjZA$@", // invalid base64 hash
	} {
		if err := VerifyPassword("anything", bad); err == nil {
			t.Errorf("input %q: expected error", bad)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
