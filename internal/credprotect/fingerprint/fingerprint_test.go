// @spec system-credential-protection
//
// The fingerprint keyring (spec C-15 to C-17): the identifier formula, a
// keyring that initializes only when provably new, every state that must
// be refused, the re-wrap and its recovery, and that re-wrapping touches
// nothing but the key rows.

package fingerprint

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

// gcm is a stand-in for the credential encryption key: AES-256-GCM, as
// secretkey uses. failEncryptAfter makes Encrypt fail after that many
// calls, to interrupt a re-wrap.
type gcm struct {
	aead             cipher.AEAD
	mu               sync.Mutex
	calls            int
	failEncryptAfter int
	// corrupt makes Encrypt wrap other bytes than it was given.
	corrupt bool
}

func newGCM(t *testing.T) *gcm {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		t.Fatal(err)
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		t.Fatal(err)
	}
	return &gcm{aead: a}
}

func (g *gcm) Encrypt(p []byte) ([]byte, error) {
	g.mu.Lock()
	g.calls++
	n := g.calls
	g.mu.Unlock()
	if g.failEncryptAfter > 0 && n > g.failEncryptAfter {
		return nil, errors.New("injected encryption failure")
	}
	if g.corrupt {
		p = make([]byte, len(p))
	}
	nonce := make([]byte, g.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.aead.Seal(nonce, nonce, p, nil), nil
}

func (g *gcm) Decrypt(c []byte) ([]byte, error) {
	n := g.aead.NonceSize()
	if len(c) < n {
		return nil, errors.New("short")
	}
	return g.aead.Open(nil, c[:n], c[n:], nil)
}

var now = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// fresh returns a pool on this package's database with the keyring back
// in the migration's starting state and no protection state.
func fresh(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, q := range []string{
		`TRUNCATE credprotect_verified_secrets, credprotect_verification_requests, credprotect_recoveries,
		 credprotect_submissions, credprotect_restrictions, credprotect_credential_classes,
		 credprotect_directory_bindings, credprotect_directory_resolutions, credprotect_identities,
		 credprotect_fingerprint_keys CASCADE`,
		`DELETE FROM credprotect_keyring`,
		`INSERT INTO credprotect_keyring (singleton) VALUES (true)`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return pool
}

func mustLoad(t *testing.T, pool *pgxpool.Pool, w Wrapper) Keyring {
	t.Helper()
	kr, err := Load(context.Background(), pool, w, now)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return kr
}

// block records a block on a password, with the given aliases, the way
// credprotect stores it.
func block(t *testing.T, pool *pgxpool.Pool, aliases []Alias) {
	t.Helper()
	ctx := context.Background()
	ident := uuid.Must(uuid.NewV7())
	// Each block gets an identity of its own; one root per username.
	if _, err := pool.Exec(ctx, `INSERT INTO credprotect_identities (id, scope, username, created_at)
		VALUES ($1, 'unconfirmed', $2, $3)`, ident, "user-"+ident.String(), now); err != nil {
		t.Fatal(err)
	}
	var keyIDs []string
	var ids [][]byte
	for _, a := range aliases {
		keyIDs = append(keyIDs, a.KeyID)
		id := a.ID
		ids = append(ids, id[:])
	}
	if _, err := pool.Exec(ctx, `INSERT INTO credprotect_restrictions
		(id, identity_id, kind, secret_kind, alias_key_ids, alias_ids, reason, created_at)
		VALUES ($1, $2, 'block', 'password', $3, $4, 'rejected', $5)`,
		uuid.Must(uuid.NewV7()), ident, keyIDs, ids, now); err != nil {
		t.Fatal(err)
	}
}

func wantCause(t *testing.T, err error, c Cause) *UnavailableError {
	t.Helper()
	var u *UnavailableError
	if !errors.As(err, &u) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want an UnavailableError with cause %s", err, c)
	}
	if u.Cause != c {
		t.Fatalf("cause = %s, want %s: %v", u.Cause, c, err)
	}
	return u
}

func wrappedRows(t *testing.T, pool *pgxpool.Pool) map[string]string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT id::text, encode(wrapped, 'hex') FROM credprotect_fingerprint_keys`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, w string
		if err := rows.Scan(&id, &w); err != nil {
			t.Fatal(err)
		}
		out[id] = w
	}
	return out
}

// @ac AC-18
func TestFingerprint_Identifier(t *testing.T) {
	t.Run("system-credential-protection/AC-18", func(t *testing.T) {
		// Known answer, computed independently with Python's hmac:
		// HMAC-SHA256(bytes(range(32)), b"ops\x00correct horse battery staple").
		material := make([]byte, 32)
		for i := range material {
			material[i] = byte(i)
		}
		want := "e0c0e8175f4e3f3e00c50c6078503c934265c7334c3242adfa7597e593d54c16" // pragma: allowlist secret
		for _, u := range []string{"ops", "  OPS ", "Ops"} {
			id := identify(material, u, "correct horse battery staple")
			if got := hex.EncodeToString(id[:]); got != want {
				t.Errorf("identify(%q) = %s, want %s", u, got, want)
			}
		}
		// The zero byte keeps the username and password apart.
		a := identify(material, "op", "s\x00x")
		b := identify(material, "ops", "x")
		if a == b {
			t.Error("username and password run together")
		}
		other := identify(make([]byte, 32), "ops", "correct horse battery staple")
		if hex.EncodeToString(other[:]) == want {
			t.Error("a different key gives the same identifier")
		}
		kr := Keyring{Generation: 3, keys: []key{
			{id: uuid.MustParse("00000000-0000-7000-8000-000000000001"), material: material, current: true},
			{id: uuid.MustParse("00000000-0000-7000-8000-000000000002"), material: make([]byte, 32)},
		}}
		al := kr.Password("ops", "correct horse battery staple")
		if len(al) != 2 || al[0].KeyID != kr.keys[0].id.String() || hex.EncodeToString(al[0].ID[:]) != want {
			t.Errorf("aliases %v: want one per key, the current first", al)
		}
		for _, s := range []string{fmt.Sprint(al[0]), fmt.Sprintf("%v", al), fmt.Sprintf("%#v", al[0])} {
			if strings.Contains(s, want[:16]) || strings.Contains(s, fmt.Sprint(al[0].ID[0])) && strings.Contains(s, "[") {
				t.Errorf("an alias prints its identifier: %s", s)
			}
		}
	})
}

// @ac AC-19
func TestFingerprint_LoadInitializesOnlyANewKeyring(t *testing.T) {
	t.Run("system-credential-protection/AC-19", func(t *testing.T) {
		ctx := context.Background()
		t.Run("new keyring", func(t *testing.T) {
			pool := fresh(t)
			w := newGCM(t)
			kr := mustLoad(t, pool, w)
			if kr.Generation != 1 || len(kr.KeyIDs()) != 1 {
				t.Fatalf("generation %d, keys %v", kr.Generation, kr.KeyIDs())
			}
			again := mustLoad(t, pool, w)
			if again.Generation != 1 || again.KeyIDs()[0] != kr.KeyIDs()[0] ||
				again.Password("ops", "pw")[0] != kr.Password("ops", "pw")[0] {
				t.Error("a second load did not return the same key")
			}
			rep, err := Verify(ctx, pool, w)
			if err != nil || rep.Keys != 1 {
				t.Errorf("verify: %v %+v", err, rep)
			}
		})
		refusals := []struct {
			name  string
			setup func(t *testing.T, pool *pgxpool.Pool, w Wrapper)
			cause Cause
		}{
			{"the keyring row is missing", func(t *testing.T, pool *pgxpool.Pool, _ Wrapper) {
				exec(t, pool, `DELETE FROM credprotect_keyring`)
			}, CauseRowMissing},
			{"not initialized, but key rows exist", func(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
				mustLoad(t, pool, w)
				exec(t, pool, `UPDATE credprotect_keyring SET initialized_at = NULL`)
			}, CauseInconsistent},
			{"not initialized, but password identifiers exist", func(t *testing.T, pool *pgxpool.Pool, _ Wrapper) {
				block(t, pool, []Alias{{KeyID: uuid.NewString()}})
			}, CauseInconsistent},
			{"initialized, no key rows", func(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
				mustLoad(t, pool, w)
				exec(t, pool, `DELETE FROM credprotect_fingerprint_keys`)
			}, CauseKeysDeleted},
			{"an identifier under a key the keyring lacks", func(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
				mustLoad(t, pool, w)
				block(t, pool, []Alias{{KeyID: uuid.NewString()}})
			}, CauseKeyMissing},
			{"no current key", func(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
				mustLoad(t, pool, w)
				exec(t, pool, `UPDATE credprotect_fingerprint_keys SET is_current = false`)
			}, CauseInconsistent},
			{"a key the encryption key cannot unwrap", func(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
				mustLoad(t, pool, newGCM(t))
			}, CauseUnwrap},
			{"a key of the wrong length", func(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
				mustLoad(t, pool, w)
				short, err := w.Encrypt(make([]byte, 16))
				if err != nil {
					t.Fatal(err)
				}
				exec(t, pool, `UPDATE credprotect_fingerprint_keys SET wrapped = $1`, short)
			}, CauseBadLength},
		}
		for _, c := range refusals {
			t.Run(c.name, func(t *testing.T) {
				pool := fresh(t)
				w := newGCM(t)
				c.setup(t, pool, w)
				before := wrappedRows(t, pool)
				_, err := Load(ctx, pool, w, now)
				u := wantCause(t, err, c.cause)
				if after := wrappedRows(t, pool); fmt.Sprint(before) != fmt.Sprint(after) {
					t.Error("a refused load changed the key rows")
				}
				_, verr := Verify(ctx, pool, w)
				_ = wantCause(t, verr, c.cause)
				// A key that is gone cannot be re-wrapped back; only an
				// unwrap failure points to the re-wrap.
				if mentions := strings.Contains(u.Remedy(), "rewrap"); mentions != (c.cause == CauseUnwrap) {
					t.Errorf("remedy for %s: %q", c.cause, u.Remedy())
				}
			})
		}
	})
}

func exec(t *testing.T, pool *pgxpool.Pool, q string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// @ac AC-20
func TestFingerprint_Concurrency(t *testing.T) {
	t.Run("system-credential-protection/AC-20", func(t *testing.T) {
		ctx := context.Background()
		t.Run("an initializer that finds the keyring initialized loads it", func(t *testing.T) {
			// The losing side of the race, made deterministic: by the time
			// it holds the keyring row, another process has initialized it.
			pool := fresh(t)
			w := newGCM(t)
			winner := mustLoad(t, pool, w)
			loser, err := initialize(ctx, pool, w, now)
			if err != nil {
				t.Fatalf("the loser was refused: %v", err)
			}
			if loser.KeyIDs()[0] != winner.KeyIDs()[0] || loser.Generation != winner.Generation {
				t.Error("the loser does not hold the winner's keyring")
			}
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM credprotect_fingerprint_keys`).Scan(&n); err != nil || n != 1 {
				t.Errorf("%d key rows, err %v", n, err)
			}
		})
		t.Run("initialization waits for an operation holding the keyring", func(t *testing.T) {
			pool := fresh(t)
			w := newGCM(t)
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tx.Rollback(ctx) })
			if _, err := tx.Exec(ctx, `SELECT 1 FROM credprotect_keyring WHERE singleton FOR SHARE`); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := initialize(ctx, pool, w, now)
				done <- err
			}()
			select {
			case err := <-done:
				t.Fatalf("initialization finished while another operation held the keyring: %v", err)
			case <-time.After(300 * time.Millisecond):
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatalf("initialize: %v", err)
			}
		})
		t.Run("two initializations race; one key results", func(t *testing.T) {
			for round := 0; round < 5; round++ {
				pool := fresh(t)
				w := newGCM(t)
				var wg sync.WaitGroup
				got := make([]Keyring, 2)
				errs := make([]error, 2)
				for i := range got {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						got[i], errs[i] = Load(ctx, pool, w, now)
					}(i)
				}
				wg.Wait()
				if errs[0] != nil || errs[1] != nil {
					t.Fatalf("round %d: %v %v", round, errs[0], errs[1])
				}
				if got[0].KeyIDs()[0] != got[1].KeyIDs()[0] {
					t.Fatalf("round %d: the racers hold different keys", round)
				}
				var n int
				if err := pool.QueryRow(ctx, `SELECT count(*) FROM credprotect_fingerprint_keys`).Scan(&n); err != nil || n != 1 {
					t.Fatalf("round %d: %d key rows, err %v", round, n, err)
				}
			}
		})
		t.Run("a re-wrap waits for an operation holding the keyring", func(t *testing.T) {
			pool := fresh(t)
			old, cur := newGCM(t), newGCM(t)
			mustLoad(t, pool, old)
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := tx.Exec(ctx, `SELECT 1 FROM credprotect_keyring WHERE singleton FOR SHARE`); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := Rewrap(ctx, pool, old, cur)
				done <- err
			}()
			select {
			case err := <-done:
				t.Fatalf("the re-wrap finished while an operation held the keyring: %v", err)
			case <-time.After(300 * time.Millisecond):
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatalf("re-wrap: %v", err)
			}
		})
	})
}

// @ac AC-21
func TestFingerprint_Rewrap(t *testing.T) {
	t.Run("system-credential-protection/AC-21", func(t *testing.T) {
		ctx := context.Background()
		t.Run("re-wraps, keeps every key, and a retry changes nothing", func(t *testing.T) {
			pool := fresh(t)
			old, cur := newGCM(t), newGCM(t)
			kr := mustLoad(t, pool, old)
			aliases := kr.Password("ops", "pw")
			block(t, pool, aliases)
			rep, err := Rewrap(ctx, pool, old, cur)
			if err != nil || rep.AlreadyRewrapped || rep.Keys != 1 || rep.WrapEpoch != 1 {
				t.Fatalf("re-wrap: %v %+v", err, rep)
			}
			after := mustLoad(t, pool, cur)
			if after.Generation != kr.Generation || after.Password("ops", "pw")[0] != aliases[0] {
				t.Error("the re-wrap changed a key or the generation")
			}
			if _, err := Load(ctx, pool, old, now); err == nil {
				t.Error("the previous key still unwraps the keyring")
			}
			rows := wrappedRows(t, pool)
			rep, err = Rewrap(ctx, pool, old, cur)
			if err != nil || !rep.AlreadyRewrapped {
				t.Fatalf("retry: %v %+v", err, rep)
			}
			if fmt.Sprint(rows) != fmt.Sprint(wrappedRows(t, pool)) {
				t.Error("the retry rewrote the key rows")
			}
			// Back to the previous key, while both exist.
			if _, err := Rewrap(ctx, pool, cur, old); err != nil {
				t.Fatalf("reverse re-wrap: %v", err)
			}
			if mustLoad(t, pool, old).Password("ops", "pw")[0] != aliases[0] {
				t.Error("the reverse re-wrap changed a key")
			}
		})
		t.Run("an interrupted re-wrap changes nothing and can be retried", func(t *testing.T) {
			pool := fresh(t)
			old, cur := newGCM(t), newGCM(t)
			mustLoad(t, pool, old)
			// A second key, so the failure lands between two keys.
			addKey(t, pool, old)
			rows := wrappedRows(t, pool)
			cur.failEncryptAfter = 1
			if _, err := Rewrap(ctx, pool, old, cur); err == nil {
				t.Fatal("the injected failure did not stop the re-wrap")
			}
			if fmt.Sprint(rows) != fmt.Sprint(wrappedRows(t, pool)) {
				t.Fatal("an interrupted re-wrap changed the key rows")
			}
			cur.failEncryptAfter = 0
			if _, err := Rewrap(ctx, pool, old, cur); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if _, err := Verify(ctx, pool, cur); err != nil {
				t.Errorf("verify after retry: %v", err)
			}
		})
		t.Run("a keyring under two keys, or neither, is refused unchanged", func(t *testing.T) {
			pool := fresh(t)
			old, cur := newGCM(t), newGCM(t)
			mustLoad(t, pool, old)
			addKey(t, pool, cur) // one row under each key
			rows := wrappedRows(t, pool)
			_, err := Rewrap(ctx, pool, old, cur)
			u := wantCause(t, err, CauseUnwrap)
			if !strings.Contains(u.Detail, "1 unwrap with the new key and 1 with the previous key") {
				t.Errorf("detail %q does not give the counts", u.Detail)
			}
			_, err = Rewrap(ctx, pool, newGCM(t), newGCM(t))
			_ = wantCause(t, err, CauseUnwrap)
			if fmt.Sprint(rows) != fmt.Sprint(wrappedRows(t, pool)) {
				t.Error("a refused re-wrap changed the key rows")
			}
		})
		t.Run("a re-wrap whose keys read back differently is reported", func(t *testing.T) {
			pool := fresh(t)
			old, cur := newGCM(t), newGCM(t)
			mustLoad(t, pool, old)
			cur.corrupt = true
			_, err := Rewrap(ctx, pool, old, cur)
			if err == nil || !strings.Contains(err.Error(), "differ from those re-wrapped") {
				t.Fatalf("err = %v, want the read-back mismatch", err)
			}
		})
		t.Run("every path validates the keyring first, the already-re-wrapped one too", func(t *testing.T) {
			cases := []struct {
				name  string
				setup func(t *testing.T, pool *pgxpool.Pool, w Wrapper)
				cause Cause
			}{
				{"not initialized", func(t *testing.T, pool *pgxpool.Pool, _ Wrapper) {}, CauseNotInitialized},
				{"no key rows", func(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
					mustLoad(t, pool, w)
					exec(t, pool, `DELETE FROM credprotect_fingerprint_keys`)
				}, CauseKeysDeleted},
				{"no current key", func(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
					mustLoad(t, pool, w)
					exec(t, pool, `UPDATE credprotect_fingerprint_keys SET is_current = false`)
				}, CauseInconsistent},
				{"an identifier's key is missing", func(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
					mustLoad(t, pool, w)
					block(t, pool, []Alias{{KeyID: uuid.NewString()}})
				}, CauseKeyMissing},
				{"a key of the wrong length", func(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
					mustLoad(t, pool, w)
					short, err := w.Encrypt(make([]byte, 16))
					if err != nil {
						t.Fatal(err)
					}
					exec(t, pool, `UPDATE credprotect_fingerprint_keys SET wrapped = $1`, short)
				}, CauseBadLength},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					pool := fresh(t)
					w := newGCM(t)
					c.setup(t, pool, w)
					// Already wrapped with w: the "already re-wrapped"
					// path, which must not succeed vacuously.
					_, err := Rewrap(ctx, pool, newGCM(t), w)
					_ = wantCause(t, err, c.cause)
					if strings.Contains(err.Error(), "committed") {
						t.Errorf("a refused re-wrap reports a commit: %v", err)
					}
					_, err = Verify(ctx, pool, w)
					_ = wantCause(t, err, c.cause)
				})
			}
		})
	})
}

// addKey adds a non-current key wrapped with w and raises the generation,
// as a later fingerprint-key rotation would.
func addKey(t *testing.T, pool *pgxpool.Pool, w Wrapper) {
	t.Helper()
	m := make([]byte, 32)
	if _, err := rand.Read(m); err != nil {
		t.Fatal(err)
	}
	wrapped, err := w.Encrypt(m)
	if err != nil {
		t.Fatal(err)
	}
	exec(t, pool, `INSERT INTO credprotect_fingerprint_keys (id, wrapped, is_current, created_at) VALUES ($1, $2, false, $3)`,
		uuid.Must(uuid.NewV7()), wrapped, now.Add(time.Second))
	exec(t, pool, `UPDATE credprotect_keyring SET generation = generation + 1`)
}

// @ac AC-22
func TestFingerprint_RewrapTouchesOnlyTheKeyRows(t *testing.T) {
	t.Run("system-credential-protection/AC-22", func(t *testing.T) {
		ctx := context.Background()
		pool := fresh(t)
		old, cur := newGCM(t), newGCM(t)
		kr := mustLoad(t, pool, old)
		block(t, pool, kr.Password("ops", "pw"))
		block(t, pool, kr.Password("svc", "other"))
		tables := []string{
			"credprotect_identities", "credprotect_directory_resolutions", "credprotect_credential_classes",
			"credprotect_directory_bindings", "credprotect_restrictions", "credprotect_submissions",
			"credprotect_recoveries", "credprotect_verification_requests", "credprotect_verified_secrets",
		}
		snapshot := func() string {
			var b strings.Builder
			for _, tbl := range tables {
				var h string
				if err := pool.QueryRow(ctx, `SELECT coalesce(string_agg(md5(t::text), ',' ORDER BY md5(t::text)), '') FROM `+tbl+` t`).Scan(&h); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256([]byte(h))
				b.WriteString(tbl + "=" + hex.EncodeToString(sum[:]) + ";")
			}
			var gen int64
			if err := pool.QueryRow(ctx, `SELECT generation FROM credprotect_keyring`).Scan(&gen); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&b, "generation=%d", gen)
			return b.String()
		}
		// A second key, so the injected failure lands between two keys.
		addKey(t, pool, old)
		before := snapshot()
		cur.failEncryptAfter = 1
		if _, err := Rewrap(ctx, pool, old, cur); err == nil {
			t.Fatal("the injected failure did not stop the re-wrap")
		}
		if snapshot() != before {
			t.Error("an interrupted re-wrap changed protection state or the generation")
		}
		cur.failEncryptAfter = 0
		if _, err := Rewrap(ctx, pool, old, cur); err != nil {
			t.Fatal(err)
		}
		if snapshot() != before {
			t.Error("a re-wrap changed protection state or the generation")
		}
		if _, err := Rewrap(ctx, pool, old, cur); err != nil {
			t.Fatal(err)
		}
		if snapshot() != before {
			t.Error("a repeated re-wrap changed protection state or the generation")
		}
	})
}
