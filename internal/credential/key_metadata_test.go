// @spec system-credential-store
//
// Key metadata is derived from the key itself (bugs/OW-123).

package credential

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/Hanalyx/openwatch/internal/sshkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"
)

// testKey is a generated private key, its PEM (encrypted when a passphrase
// was given) and the metadata a correct derivation must produce.
type testKey struct {
	pem  string
	pass string
	fp   string
	typ  string
	bits int
}

func genKey(t *testing.T, kind string, passphrase string) testKey {
	t.Helper()
	var priv crypto.PrivateKey
	var bits int
	switch kind {
	case "ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519: %v", err)
		}
		priv, bits = k, 256
	case "rsa3072", "rsa1024":
		n := map[string]int{"rsa3072": 3072, "rsa1024": 1024}[kind]
		k, err := rsa.GenerateKey(rand.Reader, n)
		if err != nil {
			t.Fatalf("rsa: %v", err)
		}
		priv, bits = k, n
	case "ecdsa256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa: %v", err)
		}
		priv, bits = k, 256
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	var blk *pem.Block
	var err error
	if passphrase != "" {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test-comment", []byte(passphrase))
	} else {
		blk, err = ssh.MarshalPrivateKey(priv, "test-comment")
	}
	if err != nil {
		t.Fatalf("marshal %s: %v", kind, err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return testKey{
		pem: string(pem.EncodeToMemory(blk)), pass: passphrase,
		fp: ssh.FingerprintSHA256(signer.PublicKey()), typ: signer.PublicKey().Type(), bits: bits,
	}
}

// testKeyPEM returns an Ed25519 key PEM for tests that need any valid key.
func testKeyPEM(t *testing.T, passphrase string) string {
	t.Helper()
	return genKey(t, "ed25519", passphrase).pem
}

type keyRow struct {
	fp, typ, comment *string
	bits             *int
	encKey, encPass  []byte
	name             string
}

func readKeyRow(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) keyRow {
	t.Helper()
	var r keyRow
	if err := pool.QueryRow(context.Background(), `
		SELECT ssh_key_fingerprint, ssh_key_type, ssh_key_comment, ssh_key_bits,
		       encrypted_private_key, encrypted_private_key_passphrase, name
		  FROM credentials WHERE id = $1`, id).
		Scan(&r.fp, &r.typ, &r.comment, &r.bits, &r.encKey, &r.encPass, &r.name); err != nil {
		t.Fatalf("read row: %v", err)
	}
	return r
}

func (r keyRow) matches(k testKey) bool {
	return r.fp != nil && *r.fp == k.fp && r.typ != nil && *r.typ == k.typ &&
		r.bits != nil && *r.bits == k.bits && r.comment == nil
}

func (r keyRow) equal(o keyRow) bool {
	eqS := func(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	eqI := func(a, b *int) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	return eqS(r.fp, o.fp) && eqS(r.typ, o.typ) && eqS(r.comment, o.comment) && eqI(r.bits, o.bits) &&
		bytes.Equal(r.encKey, o.encKey) && bytes.Equal(r.encPass, o.encPass) && r.name == o.name
}

func ptrTo[T any](v T) *T { return &v }

// @ac AC-13
// AC-13: creation derives the key metadata from the key, and refuses a key
// that does not parse with its passphrase or is too weak.
func TestKeyMetadata_DerivedOnCreate(t *testing.T) {
	t.Run("system-credential-store/AC-13", func(t *testing.T) {
		svc, pool, createdBy := freshService(t)
		ctx := context.Background()
		create := func(name string, method AuthMethod, key, pass string) (uuid.UUID, error) {
			return svc.NewCredential(ctx, NewParams{
				Scope: ScopeSystem, Name: name, Username: "u", AuthMethod: method,
				Password: "pw", PrivateKey: key, PrivateKeyPassphrase: pass, CreatedBy: createdBy,
			})
		}
		for _, tc := range []struct {
			kind, pass string
			method     AuthMethod
		}{
			{"ed25519", "", AuthSSHKey},
			{"ed25519", "ac13-passphrase", AuthSSHKey}, // pragma: allowlist secret
			{"rsa3072", "", AuthBoth},
			{"ecdsa256", "ac13-passphrase", AuthBoth}, // pragma: allowlist secret
		} {
			k := genKey(t, tc.kind, tc.pass)
			id, err := create("ac13-"+tc.kind+tc.pass, tc.method, k.pem, k.pass)
			if err != nil {
				t.Fatalf("%s (passphrase %v): %v", tc.kind, tc.pass != "", err)
			}
			if r := readKeyRow(t, pool, id); !r.matches(k) {
				t.Errorf("%s (passphrase %v): stored fp=%v type=%v bits=%v comment=%v, want %s %s %d and no comment",
					tc.kind, tc.pass != "", deref(r.fp), deref(r.typ), r.bits, r.comment, k.fp, k.typ, k.bits)
			}
		}

		// A password-only credential has no key metadata.
		id, err := create("ac13-password", AuthPassword, "", "")
		if err != nil {
			t.Fatalf("password credential: %v", err)
		}
		if r := readKeyRow(t, pool, id); r.fp != nil || r.typ != nil || r.bits != nil {
			t.Errorf("password credential has key metadata: %+v", r)
		}

		// Refusals store nothing.
		enc := genKey(t, "ed25519", "right-passphrase") // pragma: allowlist secret
		for name, tc := range map[string]struct {
			key, pass string
			want      error
		}{
			"garbage":            {garbageKeyPEM, "", sshkey.ErrInvalidKey},
			"wrong passphrase":   {enc.pem, "wrong-passphrase", sshkey.ErrInvalidKey}, // pragma: allowlist secret
			"missing passphrase": {enc.pem, "", sshkey.ErrInvalidKey},
			"weak RSA":           {genKey(t, "rsa1024", "").pem, "", sshkey.ErrWeakKey},
		} {
			if _, err := create("ac13-refused-"+name, AuthSSHKey, tc.key, tc.pass); !errors.Is(err, tc.want) {
				t.Errorf("%s: %v, want %v", name, err, tc.want)
			}
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE name LIKE 'ac13-refused-%'`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 0 {
			t.Fatalf("refused keys stored %d rows", n)
		}
	})
}

// garbageKeyPEM has a private-key PEM frame around content that is not a
// key. Built from parts so secret scanners do not mistake it for one.
var garbageKeyPEM = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nfake\n-----END " + "OPENSSH PRIVATE KEY-----"

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// @ac AC-14
// AC-14: an update derives the metadata of the key the credential will hold,
// and a failed update changes nothing.
func TestKeyMetadata_FollowsUpdates(t *testing.T) {
	t.Run("system-credential-store/AC-14", func(t *testing.T) {
		svc, pool, createdBy := freshService(t)
		ctx := context.Background()
		a := genKey(t, "ed25519", "")
		id, err := svc.NewCredential(ctx, NewParams{
			Scope: ScopeSystem, Name: "ac14", Username: "u", AuthMethod: AuthSSHKey,
			PrivateKey: a.pem, CreatedBy: createdBy,
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		update := func(p UpdateParams) error {
			p.ID = id
			_, err := svc.Update(ctx, p)
			return err
		}

		// Replace with an encrypted key and its passphrase.
		b := genKey(t, "rsa3072", "ac14-b-passphrase") // pragma: allowlist secret
		if err := update(UpdateParams{PrivateKey: &b.pem, PrivateKeyPassphrase: &b.pass}); err != nil {
			t.Fatalf("replace with encrypted key: %v", err)
		}
		if r := readKeyRow(t, pool, id); !r.matches(b) {
			t.Fatalf("after replacement metadata = %v %v %v, want %s", deref(r.fp), deref(r.typ), r.bits, b.fp)
		}

		// Failed updates leave the row exactly as it was.
		before := readKeyRow(t, pool, id)
		weak := genKey(t, "rsa1024", "")
		for name, p := range map[string]UpdateParams{
			"garbage key":                  {PrivateKey: ptrTo("not a key"), Name: ptrTo("renamed")},
			"weak key":                     {PrivateKey: &weak.pem, Name: ptrTo("renamed")},
			"wrong passphrase only":        {PrivateKeyPassphrase: ptrTo("wrong-passphrase"), Name: ptrTo("renamed")}, // pragma: allowlist secret
			"encrypted key, no passphrase": {PrivateKey: ptrTo(genKey(t, "ed25519", "other").pem), Name: ptrTo("renamed")},
		} {
			if err := update(p); !errors.Is(err, sshkey.ErrInvalidKey) && !errors.Is(err, sshkey.ErrWeakKey) {
				t.Errorf("%s: %v, want a key error", name, err)
			}
			if after := readKeyRow(t, pool, id); !after.equal(before) {
				t.Errorf("%s: the failed update changed the row", name)
			}
		}

		// The correct passphrase alone is accepted and keeps the metadata.
		if err := update(UpdateParams{PrivateKeyPassphrase: &b.pass}); err != nil {
			t.Fatalf("passphrase-only update: %v", err)
		}
		if r := readKeyRow(t, pool, id); !r.matches(b) {
			t.Fatalf("passphrase-only update changed the metadata")
		}

		// A new unencrypted key replaces the old key's passphrase too.
		c := genKey(t, "ecdsa256", "")
		if err := update(UpdateParams{PrivateKey: &c.pem}); err != nil {
			t.Fatalf("replace with unencrypted key: %v", err)
		}
		if r := readKeyRow(t, pool, id); !r.matches(c) || r.encPass != nil {
			t.Fatalf("after unencrypted replacement: metadata ok=%v, passphrase kept=%v", r.matches(c), r.encPass != nil)
		}

		// A name-only change refreshes metadata a legacy row never had.
		if _, err := pool.Exec(ctx, `UPDATE credentials SET ssh_key_fingerprint = NULL, ssh_key_type = NULL,
			ssh_key_bits = NULL, ssh_key_comment = 'legacy' WHERE id = $1`, id); err != nil {
			t.Fatalf("make legacy: %v", err)
		}
		if err := update(UpdateParams{Name: ptrTo("ac14-renamed")}); err != nil {
			t.Fatalf("rename: %v", err)
		}
		if r := readKeyRow(t, pool, id); !r.matches(c) || r.name != "ac14-renamed" {
			t.Fatalf("rename did not refresh legacy metadata")
		}

		// A name-only change never fails on a stored key it cannot read;
		// it keeps the stored metadata.
		if _, err := pool.Exec(ctx, `UPDATE credentials SET encrypted_private_key = '\x00'::bytea WHERE id = $1`, id); err != nil {
			t.Fatalf("corrupt stored key: %v", err)
		}
		if err := update(UpdateParams{Name: ptrTo("ac14-renamed-again")}); err != nil {
			t.Fatalf("rename with an unreadable stored key: %v", err)
		}
		if r := readKeyRow(t, pool, id); !r.matches(c) {
			t.Fatalf("rename with an unreadable key changed the metadata")
		}

		// Narrowing to password clears the metadata.
		if err := update(UpdateParams{AuthMethod: ptrTo(AuthPassword), Password: ptrTo("pw")}); err != nil {
			t.Fatalf("narrow to password: %v", err)
		}
		if r := readKeyRow(t, pool, id); r.fp != nil || r.typ != nil || r.bits != nil {
			t.Fatalf("password-only credential kept key metadata")
		}
	})
}

// @ac AC-15
// AC-15: a clone carries the metadata of the key it copies.
func TestKeyMetadata_DerivedOnClone(t *testing.T) {
	t.Run("system-credential-store/AC-15", func(t *testing.T) {
		svc, pool, createdBy := freshService(t)
		ctx := context.Background()
		host := seedHost(t, pool, createdBy)
		k := genKey(t, "ed25519", "ac15-passphrase") // pragma: allowlist secret
		src, err := svc.NewCredential(ctx, NewParams{
			Scope: ScopeSystem, Name: "ac15", Username: "u", AuthMethod: AuthSSHKey,
			PrivateKey: k.pem, PrivateKeyPassphrase: k.pass, CreatedBy: createdBy,
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		// The source row carries stale metadata, as rows written before
		// the fix can.
		if _, err := pool.Exec(ctx, `UPDATE credentials SET ssh_key_fingerprint = 'SHA256:stale',
			ssh_key_type = 'ssh-rsa', ssh_key_bits = 1 WHERE id = $1`, src); err != nil {
			t.Fatalf("make stale: %v", err)
		}
		clone, err := svc.CloneCredential(ctx, CloneParams{SourceID: src, Scope: ScopeHost, ScopeID: &host, CreatedBy: createdBy})
		if err != nil {
			t.Fatalf("clone: %v", err)
		}
		if r := readKeyRow(t, pool, clone); !r.matches(k) {
			t.Fatalf("clone metadata = %v %v %v, want derived %s", deref(r.fp), deref(r.typ), r.bits, k.fp)
		}

		// A source whose key cannot be read: the clone copies its stored
		// metadata as before.
		if _, err := pool.Exec(ctx, `UPDATE credentials SET encrypted_private_key = '\x00'::bytea WHERE id = $1`, src); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		clone2, err := svc.CloneCredential(ctx, CloneParams{SourceID: src, Scope: ScopeHost, ScopeID: &host, Name: "ac15-second", CreatedBy: createdBy})
		if err != nil {
			t.Fatalf("clone of an unreadable key: %v", err)
		}
		if r := readKeyRow(t, pool, clone2); r.fp == nil || *r.fp != "SHA256:stale" {
			t.Fatalf("clone of an unreadable key: fp %v, want the source's stored value", deref(r.fp))
		}
	})
}

// @ac AC-15
// AC-15 (ciphertext): deriving the clone's metadata decrypts the source's
// key and passphrase in memory only. The clone's encrypted columns are the
// source's ciphertext byte for byte, not a re-encryption.
func TestKeyMetadata_CloneCopiesCiphertext(t *testing.T) {
	t.Run("system-credential-store/AC-15", func(t *testing.T) {
		svc, pool, createdBy := freshService(t)
		ctx := context.Background()
		host := seedHost(t, pool, createdBy)
		k := genKey(t, "ecdsa256", "ac15-ct-passphrase") // pragma: allowlist secret
		src, err := svc.NewCredential(ctx, NewParams{
			Scope: ScopeSystem, Name: "ac15-ct", Username: "u", AuthMethod: AuthBoth,
			Password: "pw", PrivateKey: k.pem, PrivateKeyPassphrase: k.pass, CreatedBy: createdBy,
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		clone, err := svc.CloneCredential(ctx, CloneParams{SourceID: src, Scope: ScopeHost, ScopeID: &host, CreatedBy: createdBy})
		if err != nil {
			t.Fatalf("clone: %v", err)
		}
		cipher := func(id uuid.UUID) (pw, key, pass []byte) {
			t.Helper()
			if err := pool.QueryRow(ctx, `SELECT encrypted_password, encrypted_private_key,
				encrypted_private_key_passphrase FROM credentials WHERE id = $1`, id).Scan(&pw, &key, &pass); err != nil {
				t.Fatalf("read ciphertext: %v", err)
			}
			return pw, key, pass
		}
		sPw, sKey, sPass := cipher(src)
		cPw, cKey, cPass := cipher(clone)
		if !bytes.Equal(sPw, cPw) || !bytes.Equal(sKey, cKey) || !bytes.Equal(sPass, cPass) {
			t.Fatalf("clone ciphertext differs from the source's (password %v, key %v, passphrase %v)",
				!bytes.Equal(sPw, cPw), !bytes.Equal(sKey, cKey), !bytes.Equal(sPass, cPass))
		}
		if r := readKeyRow(t, pool, clone); !r.matches(k) {
			t.Fatalf("clone metadata = %v, want derived %s", deref(r.fp), k.fp)
		}
	})
}
