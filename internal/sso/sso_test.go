// @spec system-sso
//
// Provider CRUD + the OIDC authorization-code flow validated against a stub
// IdP (a locally generated RSA key stands in for the provider's signing
// key). DSN-gated via OPENWATCH_TEST_DSN.

package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// idp is a stub OIDC provider. Tests mutate its fields to drive the
// happy path and the rejection paths.
type idp struct {
	*httptest.Server
	key       *rsa.PrivateKey // JWKS-advertised key
	signKey   *rsa.PrivateKey // key used to sign id_tokens (defaults to key)
	kid       string
	clientID  string
	nonce     string // embedded in the next id_token
	aud       string // override audience (default clientID)
	sub       string
	email     string
	badIssuer bool
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	d := &idp{key: key, signKey: key, kid: "test-kid", sub: "sub-123", email: "alice@example.com"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		iss := d.URL
		if d.badIssuer {
			iss = "https://evil.example.com"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 iss,
			"authorization_endpoint": d.URL + "/authorize",
			"token_endpoint":         d.URL + "/token",
			"jwks_uri":               d.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := d.key.Public().(*rsa.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "use": "sig", "kid": d.kid,
				"n": b64(pub.N.Bytes()),
				"e": b64(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		aud := d.aud
		if aud == "" {
			aud = d.clientID
		}
		claims := jwt.MapClaims{
			"iss": d.URL, "sub": d.sub, "aud": aud,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"nonce": d.nonce, "email": d.email, "email_verified": true,
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = d.kid
		signed, err := tok.SignedString(d.signKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token": signed, "access_token": "at", "token_type": "Bearer",
		})
	})
	ts := httptest.NewTLSServer(mux)
	d.Server = ts
	t.Cleanup(ts.Close)
	return d
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func freshSSO(t *testing.T) (*Service, *pgxpool.Pool, *idp) {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run sso tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	pool, err := db.NewPool(ctx, dsn, 5)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if err := secretkey.SetEphemeral(); err != nil {
		t.Fatalf("secretkey: %v", err)
	}
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE sso_providers CASCADE")
	_, _ = pool.Exec(ctx, "DELETE FROM users WHERE username LIKE 'alice%' OR username LIKE 'sso-%'")
	d := newIDP(t)
	d.clientID = "client-abc"
	svc := NewService(pool).WithHTTP(d.Client())
	return svc, pool, d
}

func mkProvider(t *testing.T, svc *Service, d *idp) Provider {
	t.Helper()
	p, err := svc.Create(context.Background(), CreateParams{
		Name: "Acme", Issuer: d.URL, ClientID: d.clientID,
		ClientSecret: "topsecret", DefaultRole: "viewer", Enabled: true,
	})
	if err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	return p
}

// @ac AC-01
func TestSSO_CreateEncryptsAndValidates(t *testing.T) {
	t.Run("system-sso/AC-01", func(t *testing.T) {
		svc, pool, d := freshSSO(t)
		ctx := context.Background()
		p := mkProvider(t, svc, d)

		// Stored secret is ciphertext, not the plaintext bytes.
		var enc []byte
		_ = pool.QueryRow(ctx, `SELECT client_secret_enc FROM sso_providers WHERE id=$1`, p.ID).Scan(&enc)
		if strings.Contains(string(enc), "topsecret") {
			t.Error("stored client secret is not encrypted")
		}
		// Non-https issuer rejected.
		if _, err := svc.Create(ctx, CreateParams{Name: "x", Issuer: "http://idp", ClientID: "c", ClientSecret: "s"}); err == nil {
			t.Error("http issuer accepted, want ErrInvalidParams")
		}
		// Missing client_secret rejected.
		if _, err := svc.Create(ctx, CreateParams{Name: "x", Issuer: "https://idp", ClientID: "c"}); err == nil {
			t.Error("missing secret accepted, want ErrInvalidParams")
		}
	})
}

// @ac AC-02
func TestSSO_UpdateSecretOptional(t *testing.T) {
	t.Run("system-sso/AC-02", func(t *testing.T) {
		svc, pool, d := freshSSO(t)
		ctx := context.Background()
		p := mkProvider(t, svc, d)

		var before []byte
		_ = pool.QueryRow(ctx, `SELECT client_secret_enc FROM sso_providers WHERE id=$1`, p.ID).Scan(&before)
		// Update without a secret keeps the stored one.
		if _, err := svc.Update(ctx, p.ID, UpdateParams{
			Name: "Acme2", Issuer: d.URL, ClientID: d.clientID, DefaultRole: "viewer", Enabled: true,
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		var after []byte
		_ = pool.QueryRow(ctx, `SELECT client_secret_enc FROM sso_providers WHERE id=$1`, p.ID).Scan(&after)
		if string(before) != string(after) {
			t.Error("empty client_secret changed the stored secret")
		}
		// Unknown id → not found.
		if _, err := svc.Update(ctx, uuid.New(), UpdateParams{Name: "x", Issuer: "https://i", ClientID: "c"}); err == nil {
			t.Error("update unknown id succeeded, want ErrProviderNotFound")
		}
	})
}

// @ac AC-03
func TestSSO_BuildAuthURL(t *testing.T) {
	t.Run("system-sso/AC-03", func(t *testing.T) {
		svc, pool, d := freshSSO(t)
		ctx := context.Background()
		p := mkProvider(t, svc, d)

		authURL, err := svc.BuildAuthURL(ctx, p.ID.String(), "https://app/cb", "/dashboard")
		if err != nil {
			t.Fatalf("BuildAuthURL: %v", err)
		}
		u, _ := url.Parse(authURL)
		q := u.Query()
		if q.Get("response_type") != "code" || q.Get("client_id") != d.clientID ||
			q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" {
			t.Errorf("auth url missing required params: %s", authURL)
		}
		if !strings.Contains(q.Get("scope"), "openid") {
			t.Errorf("scope missing openid: %q", q.Get("scope"))
		}
		// The persisted state's verifier S256-hashes to the challenge.
		var verifier, nonce string
		_ = pool.QueryRow(ctx, `SELECT code_verifier, nonce FROM sso_auth_states WHERE state=$1`,
			q.Get("state")).Scan(&verifier, &nonce)
		if nonce != q.Get("nonce") {
			t.Error("persisted nonce != auth-url nonce")
		}
		sum := sha256.Sum256([]byte(verifier))
		if b64(sum[:]) != q.Get("code_challenge") {
			t.Error("code_challenge is not S256(verifier)")
		}
	})
}

// @ac AC-04
func TestSSO_DiscoveryValidatesIssuer(t *testing.T) {
	t.Run("system-sso/AC-04", func(t *testing.T) {
		svc, _, d := freshSSO(t)
		d.badIssuer = true
		p := mkProvider(t, svc, d)
		if _, err := svc.BuildAuthURL(context.Background(), p.ID.String(), "https://app/cb", "/"); err == nil {
			t.Error("discovery accepted mismatched issuer, want ErrDiscovery")
		}
	})
}

// @ac AC-05
func TestSSO_AuthStateSingleUse(t *testing.T) {
	t.Run("system-sso/AC-05", func(t *testing.T) {
		svc, _, d := freshSSO(t)
		ctx := context.Background()
		p := mkProvider(t, svc, d)
		st := AuthState{State: "s1", ProviderID: p.ID, Nonce: "n", CodeVerifier: "v",
			RedirectTo: "/", ExpiresAt: time.Now().Add(time.Minute)}
		if err := svc.saveAuthState(ctx, st); err != nil {
			t.Fatalf("save: %v", err)
		}
		if _, err := svc.consumeAuthState(ctx, "s1"); err != nil {
			t.Fatalf("first consume: %v", err)
		}
		if _, err := svc.consumeAuthState(ctx, "s1"); err == nil {
			t.Error("second consume succeeded, want ErrStateNotFound")
		}
		// Expired state.
		exp := AuthState{State: "s2", ProviderID: p.ID, Nonce: "n", CodeVerifier: "v",
			RedirectTo: "/", ExpiresAt: time.Now().Add(-time.Minute)}
		_ = svc.saveAuthState(ctx, exp)
		if _, err := svc.consumeAuthState(ctx, "s2"); err == nil {
			t.Error("expired consume succeeded, want ErrStateExpired")
		}
	})
}

// startLogin runs BuildAuthURL and syncs the IdP's id_token nonce to the
// persisted state so a subsequent callback validates.
func startLogin(t *testing.T, svc *Service, pool *pgxpool.Pool, d *idp, p Provider) string {
	t.Helper()
	authURL, err := svc.BuildAuthURL(context.Background(), p.ID.String(), "https://app/cb", "/dashboard")
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(authURL)
	state := u.Query().Get("state")
	_ = pool.QueryRow(context.Background(),
		`SELECT nonce FROM sso_auth_states WHERE state=$1`, state).Scan(&d.nonce)
	return state
}

// @ac AC-06
func TestSSO_CallbackValidatesIDToken(t *testing.T) {
	t.Run("system-sso/AC-06", func(t *testing.T) {
		svc, pool, d := freshSSO(t)
		ctx := context.Background()
		p := mkProvider(t, svc, d)
		provision := provisionInto(pool)

		// Happy path.
		state := startLogin(t, svc, pool, d, p)
		res, err := svc.HandleCallback(ctx, state, "https://app/cb", "code", provision)
		if err != nil {
			t.Fatalf("HandleCallback happy: %v", err)
		}
		if res.UserID == uuid.Nil || !res.Provisioned {
			t.Errorf("expected a provisioned user, got %+v", res)
		}

		// Bad signature: sign with a different key than the JWKS advertises.
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		d.signKey = other
		state = startLogin(t, svc, pool, d, p)
		if _, err := svc.HandleCallback(ctx, state, "https://app/cb", "code", provision); err == nil {
			t.Error("accepted a token with a bad signature")
		}
		d.signKey = d.key

		// Wrong nonce.
		state = startLogin(t, svc, pool, d, p)
		d.nonce = "tampered"
		if _, err := svc.HandleCallback(ctx, state, "https://app/cb", "code", provision); err == nil {
			t.Error("accepted a token with a mismatched nonce")
		}

		// Wrong audience.
		state = startLogin(t, svc, pool, d, p)
		d.aud = "someone-else"
		if _, err := svc.HandleCallback(ctx, state, "https://app/cb", "code", provision); err == nil {
			t.Error("accepted a token with the wrong audience")
		}
		d.aud = ""
	})
}

// @ac AC-07
func TestSSO_CallbackProvisionThenReuse(t *testing.T) {
	t.Run("system-sso/AC-07", func(t *testing.T) {
		svc, pool, d := freshSSO(t)
		ctx := context.Background()
		p := mkProvider(t, svc, d)
		provision := provisionInto(pool)

		state := startLogin(t, svc, pool, d, p)
		first, err := svc.HandleCallback(ctx, state, "https://app/cb", "code", provision)
		if err != nil {
			t.Fatalf("first callback: %v", err)
		}
		if !first.Provisioned {
			t.Fatal("first sign-in should provision")
		}
		// Second sign-in for the same subject reuses the user.
		state = startLogin(t, svc, pool, d, p)
		second, err := svc.HandleCallback(ctx, state, "https://app/cb", "code", provision)
		if err != nil {
			t.Fatalf("second callback: %v", err)
		}
		if second.Provisioned {
			t.Error("second sign-in should not re-provision")
		}
		if second.UserID != first.UserID {
			t.Errorf("second sign-in returned a different user: %s != %s", second.UserID, first.UserID)
		}
	})
}

// provisionInto returns a ProvisionFunc that inserts a minimal user row so
// the sso_identities FK is satisfied — standing in for users.CreateFederatedUser.
func provisionInto(pool *pgxpool.Pool) ProvisionFunc {
	return func(ctx context.Context, username, email, _ string) (uuid.UUID, error) {
		id, _ := uuid.NewV7()
		_, err := pool.Exec(ctx,
			`INSERT INTO users (id, username, email, password_hash) VALUES ($1,$2,$3,'x')`,
			id, username, email)
		return id, err
	}
}
