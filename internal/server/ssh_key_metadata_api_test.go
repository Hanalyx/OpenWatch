// @spec api-credentials

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"golang.org/x/crypto/ssh"
)

// genEd25519 returns an OpenSSH PEM (encrypted when passphrase is set) and
// the fingerprint ssh.FingerprintSHA256 gives its public key.
func genEd25519(t *testing.T, passphrase string) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	var blk *pem.Block
	if passphrase != "" {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	} else {
		blk, err = ssh.MarshalPrivateKey(priv, "")
	}
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return string(pem.EncodeToMemory(blk)), ssh.FingerprintSHA256(signer.PublicKey())
}

type credMeta struct {
	ID          string `json:"id"`
	Fingerprint string `json:"ssh_key_fingerprint"`
	Type        string `json:"ssh_key_type"`
	Bits        int    `json:"ssh_key_bits"`
	Error       struct {
		Code string `json:"code"`
	} `json:"error"`
}

func credCall(t *testing.T, method, url string, body any) (int, credMeta) {
	t.Helper()
	resp := doReq(t, asRole(t, method, url, auth.RoleAdmin, body))
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var m credMeta
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

// @ac AC-22
// AC-22: the API returns and stores the metadata of the key it was given,
// through create, replacement and clone, and a refused change leaves the
// credential as it was.
func TestCredentials_KeyMetadataFromTheKey(t *testing.T) {
	t.Run("api-credentials/AC-22", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()

		keyA, fpA := genEd25519(t, "")
		st, created := credCall(t, "POST", url+"/api/v1/credentials", map[string]any{
			"scope": "system", "name": "ac22", "username": "ops", "auth_method": "ssh_key", "private_key": keyA,
		})
		if st != http.StatusCreated || created.Fingerprint != fpA || created.Type != "ssh-ed25519" || created.Bits != 256 {
			t.Fatalf("create = %d %+v, want 201 with %s ssh-ed25519 256", st, created, fpA)
		}
		var stored string
		if err := pool.QueryRow(ctx, `SELECT ssh_key_fingerprint FROM credentials WHERE id = $1`, created.ID).Scan(&stored); err != nil || stored != fpA {
			t.Fatalf("stored fingerprint %q (err %v), want %s", stored, err, fpA)
		}

		const passB = "ac22-b-passphrase" // pragma: allowlist secret
		keyB, fpB := genEd25519(t, passB)
		st, patched := credCall(t, "PATCH", url+"/api/v1/credentials/"+created.ID, map[string]any{
			"private_key": keyB, "private_key_passphrase": passB,
		})
		if st != http.StatusOK || patched.Fingerprint != fpB {
			t.Fatalf("replace = %d %+v, want 200 with %s", st, patched, fpB)
		}

		// A wrong passphrase alone is refused, and nothing changes.
		st, refused := credCall(t, "PATCH", url+"/api/v1/credentials/"+created.ID, map[string]any{
			"private_key_passphrase": "wrong-passphrase", "name": "ac22-renamed", // pragma: allowlist secret
		})
		if st != http.StatusBadRequest || refused.Error.Code != "credentials.invalid_key" {
			t.Fatalf("wrong passphrase = %d %s, want 400 credentials.invalid_key", st, refused.Error.Code)
		}
		st, after := credCall(t, "GET", url+"/api/v1/credentials/"+created.ID, nil)
		var name string
		_ = pool.QueryRow(ctx, `SELECT name FROM credentials WHERE id = $1`, created.ID).Scan(&name)
		if st != http.StatusOK || after.Fingerprint != fpB || name != "ac22" {
			t.Fatalf("after a refused change: fp %s name %q, want %s and ac22", after.Fingerprint, name, fpB)
		}

		// A clone carries the fingerprint of the key it copies.
		st, clone := credCall(t, "POST", url+"/api/v1/credentials/"+created.ID+":clone", map[string]any{
			"scope": "system", "name": "ac22-clone",
		})
		if st != http.StatusCreated || clone.Fingerprint != fpB {
			t.Fatalf("clone = %d %+v, want 201 with %s", st, clone, fpB)
		}
	})
}
