// @spec release-admin-signoff
//
// Runtime boot test: spawns the actual dist/openwatch binary against a
// real Postgres and confirms the full login → admin-action flow works
// end-to-end. This is the test that catches "all the unit tests pass
// but the binary itself is non-functional" — a class of bug where
// fixtures install ephemeral keys but cmd/openwatch/main.go doesn't
// wire the corresponding production key-loading code.

package packaging_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// insecureTLS skips cert verification for talking to a server using a
// self-signed demo cert. Test-only.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // self-signed test cert
}

// runtimeBootDSN returns the DSN to test the binary against. Skips
// the test when not configured, matching the in-process integration
// tests' convention.
func runtimeBootDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run runtime boot tests")
	}
	return dsn
}

// genJWTKey writes a fresh 2048-bit RSA key to path in PKCS#8 PEM.
func genJWTKey(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write jwt key: %v", err)
	}
}

// genDEK writes 32 random bytes to path.
func genDEK(t *testing.T, path string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("read dek: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write dek: %v", err)
	}
}

// genTLS produces a self-signed TLS cert + key by shelling out to the
// project's existing demo-cert script. The script handles correct
// modes and headers; reimplementing it in Go for one test isn't worth
// the duplication.
func genTLS(t *testing.T, app, outDir string) {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join(app, "packaging", "common", "gen-demo-cert.sh"), outDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen-demo-cert.sh: %v: %s", err, out)
	}
}

// freshTestDB connects to the supplied DSN with admin privileges, drops
// and recreates a dedicated boot-test database, and returns a DSN
// pointing at it. The boot test runs against an isolated DB so it
// can't collide with the in-process integration tests.
func freshTestDB(t *testing.T, parentDSN string) string {
	t.Helper()
	const testDBName = "openwatch_runtime_boot_test"
	// Connect to the maintenance DB on the same server.
	maintDSN := strings.Replace(parentDSN, "openwatch_go_test", "postgres", 1)
	// Run DROP + CREATE via the psql client inside the docker container,
	// since this Go process doesn't have a psql binary handy and pgx
	// requires a separate connection per CREATE DATABASE call.
	for _, stmt := range []string{
		fmt.Sprintf("DROP DATABASE IF EXISTS %s", testDBName),
		fmt.Sprintf("CREATE DATABASE %s", testDBName),
	} {
		cmd := exec.Command("docker", "exec", "openwatch-db",
			"psql", "-U", "openwatch", "-d", "postgres", "-c", stmt)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("can't manage test DB (docker exec): %v: %s", err, out)
		}
	}
	_ = maintDSN
	return strings.Replace(parentDSN, "openwatch_go_test", testDBName, 1)
}

// @ac AC-14
// AC-14: the v0.2.0 binary boots with the documented key paths and
// /auth/login returns a real access token + session cookie. This test
// detects the "tests-pass-but-binary-broken" class of bug by running
// `dist/openwatch serve` directly and hitting it over HTTPS.
func TestRuntimeBoot_LoginEndToEnd(t *testing.T) {
	t.Run("release-admin-signoff/AC-14", func(t *testing.T) {
		parentDSN := runtimeBootDSN(t)
		app := appDir(t)

		// Build the binary so the test runs against the current source.
		runMake(t, app, "build")
		bin := filepath.Join(app, "dist", "openwatch")
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("binary missing after make build: %v", err)
		}

		// Isolated workspace for keys + TLS + cookies.
		work := t.TempDir()
		tlsDir := filepath.Join(work, "tls")
		jwtKey := filepath.Join(work, "jwt_private.pem")
		dek := filepath.Join(work, "credential.key")
		genTLS(t, app, tlsDir)
		genJWTKey(t, jwtKey)
		genDEK(t, dek)

		testDSN := freshTestDB(t, parentDSN)
		env := append(os.Environ(),
			"OPENWATCH_DATABASE_DSN="+testDSN,
			"OPENWATCH_SERVER_TLS_CERT="+filepath.Join(tlsDir, "cert.pem"),
			"OPENWATCH_SERVER_TLS_KEY="+filepath.Join(tlsDir, "key.pem"),
			"OPENWATCH_SERVER_LISTEN=127.0.0.1:18443",
			"OPENWATCH_IDENTITY_JWT_PRIVATE_KEY="+jwtKey,
			"OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE="+dek,
		)

		// 1) Apply migrations.
		mig := exec.Command(bin, "migrate")
		mig.Env = env
		if out, err := mig.CombinedOutput(); err != nil {
			t.Fatalf("migrate: %v: %s", err, out)
		}

		// 2) Create the first admin user (closes the chicken-and-egg).
		const adminUser = "boot-test-admin"
		const adminPw = "boot-test-pw-zZ-1234567890"
		mk := exec.Command(bin, "create-admin",
			"--username", adminUser,
			"--email", adminUser+"@example.com",
			"--password", adminPw)
		mk.Env = env
		if out, err := mk.CombinedOutput(); err != nil {
			t.Fatalf("create-admin: %v: %s", err, out)
		}

		// 3) Start serve in the background.
		serve := exec.Command(bin, "serve")
		serve.Env = env
		serveOut := &bytes.Buffer{}
		serve.Stdout = serveOut
		serve.Stderr = serveOut
		// Put the server in its own process group so we can terminate
		// it cleanly via SIGTERM.
		serve.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := serve.Start(); err != nil {
			t.Fatalf("serve start: %v", err)
		}
		t.Cleanup(func() {
			_ = syscall.Kill(-serve.Process.Pid, syscall.SIGTERM)
			_, _ = serve.Process.Wait()
		})

		// 4) Wait for /health. The TLS handshake against a self-signed
		// cert needs the lenient transport.
		client := &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: insecureTLS(),
			},
		}
		base := "https://127.0.0.1:18443"
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			resp, err := client.Get(base + "/api/v1/health")
			if err == nil && resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				break
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(100 * time.Millisecond)
		}
		// Final health check; fail with full server log if still down.
		resp, err := client.Get(base + "/api/v1/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("health never ready: err=%v log=%s", err, serveOut.String())
		}
		resp.Body.Close()

		// 5) Login → expect a real access_token and session cookie.
		loginBody, _ := json.Marshal(map[string]string{
			"username": adminUser, "password": adminPw,
		})
		req, _ := http.NewRequest("POST", base+"/api/v1/auth/login", bytes.NewReader(loginBody))
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("login http: %v log=%s", err, serveOut.String())
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status = %d body=%s log=%s", resp.StatusCode, body, serveOut.String())
		}
		var loginResp struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			User         struct {
				Username string `json:"username"`
				Role     string `json:"role"`
			} `json:"user"`
		}
		if err := json.Unmarshal(body, &loginResp); err != nil {
			t.Fatalf("decode login: %v body=%s", err, body)
		}
		if loginResp.AccessToken == "" {
			t.Error("login returned empty access_token (jwt signing key not wired?)")
		}
		if loginResp.User.Username != adminUser || loginResp.User.Role != "admin" {
			t.Errorf("login user = %+v, want username=%s role=admin", loginResp.User, adminUser)
		}
		var sessCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "openwatch_session" {
				sessCookie = c
				break
			}
		}
		if sessCookie == nil {
			t.Error("login did not set openwatch_session cookie")
		}

		// 6) Use the session cookie to register a host. Exercises the
		// production identity binder + RBAC + audit pipeline.
		hostBody, _ := json.Marshal(map[string]any{
			"hostname":    "boot-test-host",
			"ip_address":  "192.0.2.99",
			"environment": "staging",
			"tags":        []string{"runtime-boot-test"},
		})
		req, _ = http.NewRequest("POST", base+"/api/v1/hosts", bytes.NewReader(hostBody))
		req.Header.Set("Content-Type", "application/json")
		if sessCookie != nil {
			req.AddCookie(sessCookie)
		}
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("create host: %v", err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create host status = %d body=%s log=%s",
				resp.StatusCode, body, serveOut.String())
		}

		// 7) Refusal to boot without keys configured — pin the failure
		// mode so a future "make it convenient" change doesn't silently
		// fall back to ephemeral keys.
		broken := append(os.Environ(),
			"OPENWATCH_DATABASE_DSN="+testDSN,
			"OPENWATCH_SERVER_TLS_CERT="+filepath.Join(tlsDir, "cert.pem"),
			"OPENWATCH_SERVER_TLS_KEY="+filepath.Join(tlsDir, "key.pem"),
			"OPENWATCH_SERVER_LISTEN=127.0.0.1:18444",
			"OPENWATCH_IDENTITY_JWT_PRIVATE_KEY=", // empty → must fail
			"OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE="+dek,
		)
		brokenServe := exec.Command(bin, "serve")
		brokenServe.Env = broken
		brokenOut, _ := brokenServe.CombinedOutput()
		if brokenServe.ProcessState.ExitCode() == 0 {
			t.Errorf("serve booted with empty jwt key — must fail; output=%s", brokenOut)
		}
		if !strings.Contains(string(brokenOut), "jwt_private_key is empty") {
			t.Errorf("missing-jwt-key error message changed; got: %s", brokenOut)
		}
	})
}
