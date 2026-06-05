// @spec system-correlation
//
// AC traceability:
// @ac AC-01  (TestGenerate_FormatPerPrefix)
// @ac AC-02  (TestGenerate_UniquenessSequential)
// @ac AC-03  (TestGenerate_UniquenessConcurrent)
// @ac AC-04  (TestGenerate_TimestampEmbedded)
// @ac AC-05  (TestSanitize_EmptyReturnsFresh)
// @ac AC-06  (TestSanitize_ValidPassesThrough)
// @ac AC-07  (TestSanitize_RejectsInvalid)
// @ac AC-08  (TestSetFromRoundtrip)
//   (AC-9..AC-16 covered in http_test.go, log handler tests, httpclient tests)

package correlation

import (
	"context"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// @ac AC-01  (Format matches ^<prefix>-[0-9a-f]{16}$ for each prefix.)
func TestGenerate_FormatPerPrefix(t *testing.T) {
	t.Run("system-correlation/AC-01", func(t *testing.T) {

		cases := []struct {
			prefix Prefix
			want   *regexp.Regexp
		}{
			{PrefixRequest, regexp.MustCompile(`^req-[0-9a-f]{16}$`)},
			{PrefixCron, regexp.MustCompile(`^cron-[0-9a-f]{16}$`)},
			{PrefixBoot, regexp.MustCompile(`^boot-[0-9a-f]{16}$`)},
			{PrefixTest, regexp.MustCompile(`^test-[0-9a-f]{16}$`)},
		}
		for _, c := range cases {
			got := Generate(c.prefix)
			if !c.want.MatchString(got) {
				t.Errorf("Generate(%q) = %q, want match %s", c.prefix, got, c.want)
			}
		}
	})
}

// @ac AC-02  (Sequential calls return distinct IDs (sampled across 10000).)
func TestGenerate_UniquenessSequential(t *testing.T) {
	t.Run("system-correlation/AC-02", func(t *testing.T) {

		const n = 10000
		seen := make(map[string]struct{}, n)
		for i := 0; i < n; i++ {
			id := Generate(PrefixRequest)
			if _, dup := seen[id]; dup {
				t.Fatalf("duplicate id at i=%d: %s", i, id)
			}
			seen[id] = struct{}{}
		}
	})
}

// @ac AC-03  (Concurrent calls produce distinct IDs (race detector + uniqueness check).)
func TestGenerate_UniquenessConcurrent(t *testing.T) {
	t.Run("system-correlation/AC-03", func(t *testing.T) {

		const n = 1000
		ids := make([]string, n)
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(i int) {
				defer wg.Done()
				ids[i] = Generate(PrefixRequest)
			}(i)
		}
		wg.Wait()

		seen := make(map[string]struct{}, n)
		for _, id := range ids {
			if _, dup := seen[id]; dup {
				t.Fatalf("duplicate id under concurrency: %s", id)
			}
			seen[id] = struct{}{}
		}
	})
}

// @ac AC-04  (The hex portion decodes as 8 bytes; first 48 bits are recent unix-millis.)
func TestGenerate_TimestampEmbedded(t *testing.T) {
	t.Run("system-correlation/AC-04", func(t *testing.T) {

		before := time.Now().UnixMilli()
		id := Generate(PrefixRequest)
		after := time.Now().UnixMilli()

		hexPart := strings.TrimPrefix(id, "req-")
		raw, err := hex.DecodeString(hexPart)
		if err != nil {
			t.Fatalf("hex decode: %v", err)
		}
		if len(raw) != 8 {
			t.Fatalf("decoded len = %d, want 8", len(raw))
		}
		// First 48 bits = unix millis.
		ms := uint64(raw[0])<<40 |
			uint64(raw[1])<<32 |
			uint64(raw[2])<<24 |
			uint64(raw[3])<<16 |
			uint64(raw[4])<<8 |
			uint64(raw[5])
		// ms is a 48-bit Unix-millis timestamp; safe to narrow into int64.
		mss := int64(ms) //nolint:gosec // 48-bit ts fits in int64
		if mss < before-10 || mss > after+10 {
			t.Errorf("embedded ts %d outside [%d, %d]", ms, before, after)
		}
	})
}

// @ac AC-05  (Empty input → fresh req- ID, regenerated=false (absence isn't rejection).)
func TestSanitize_EmptyReturnsFresh(t *testing.T) {
	t.Run("system-correlation/AC-05", func(t *testing.T) {

		id, regen := SanitizeOrGenerate("")
		if regen {
			t.Error("empty input should not flag regenerated=true")
		}
		if !strings.HasPrefix(id, "req-") {
			t.Errorf("got %q, want req- prefix", id)
		}
	})
}

// @ac AC-06  (Valid client header passes through unchanged.)
func TestSanitize_ValidPassesThrough(t *testing.T) {
	t.Run("system-correlation/AC-06", func(t *testing.T) {

		cases := []string{
			"my-id-001",
			"abc",
			"A_B_C_123",
			"req-abcd1234",
			strings.Repeat("a", 64),
		}
		for _, in := range cases {
			got, regen := SanitizeOrGenerate(in)
			if regen {
				t.Errorf("SanitizeOrGenerate(%q) flagged regenerated=true, want false", in)
			}
			if got != in {
				t.Errorf("SanitizeOrGenerate(%q) = %q, want passthrough", in, got)
			}
		}
	})
}

// @ac AC-07  (Reject oversize, out-of-charset, and reserved-prefix inputs.)
func TestSanitize_RejectsInvalid(t *testing.T) {
	t.Run("system-correlation/AC-07", func(t *testing.T) {

		rejects := []string{
			strings.Repeat("a", 65), // too long
			"has spaces",            // bad charset
			"weird:char",            // bad charset
			"boot-fake",             // reserved
			"cron-fake",             // reserved
			"test-fake",             // reserved
			"<script>",              // bad charset
			"id;DROP TABLE users",   // bad charset
		}
		for _, in := range rejects {
			got, regen := SanitizeOrGenerate(in)
			if !regen {
				t.Errorf("SanitizeOrGenerate(%q) regenerated=false, want true", in)
			}
			if !strings.HasPrefix(got, "req-") {
				t.Errorf("SanitizeOrGenerate(%q) returned %q, want req- prefix", in, got)
			}
			if got == in {
				t.Errorf("SanitizeOrGenerate(%q) returned input unchanged", in)
			}
		}
	})
}

// @ac AC-08  (Set/From round-trip; Background returns ("", false).)
func TestSetFromRoundtrip(t *testing.T) {
	t.Run("system-correlation/AC-08", func(t *testing.T) {

		ctx := Set(context.Background(), "req-deadbeef00000001")
		got, ok := From(ctx)
		if !ok || got != "req-deadbeef00000001" {
			t.Errorf("From(Set(ctx, id)) = %q, %v; want id, true", got, ok)
		}

		got2, ok2 := From(context.Background())
		if ok2 || got2 != "" {
			t.Errorf("From(Background()) = %q, %v; want '', false", got2, ok2)
		}

		// Setting empty string round-trips as ("", false) — empty is treated as absent.
		emptyCtx := Set(context.Background(), "")
		gotE, okE := From(emptyCtx)
		if okE || gotE != "" {
			t.Errorf("From(Set(ctx, '')) = %q, %v; want '', false", gotE, okE)
		}
	})
}
