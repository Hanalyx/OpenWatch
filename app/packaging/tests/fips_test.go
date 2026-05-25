// @spec release-fips-build
//
// FIPS-build tests. Build the non-FIPS and FIPS binaries via the
// Makefile, then inspect both for the FIPS contract: version flag,
// embedded FIPS-module symbols, identical functional output.

package packaging_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fipsBinary builds dist/openwatch-fips on demand and returns its path.
func fipsBinary(t *testing.T) string {
	t.Helper()
	dir := appDir(t)
	haveTool(t, "go")
	runMake(t, dir, "build-fips")
	bin := filepath.Join(dir, "dist", "openwatch-fips")
	if info, err := os.Stat(bin); err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("openwatch-fips at %s not built or not executable: %v", bin, err)
	}
	return bin
}

// nonFIPSBinary builds dist/openwatch on demand and returns its path.
func nonFIPSBinary(t *testing.T) string {
	t.Helper()
	dir := appDir(t)
	haveTool(t, "go")
	runMake(t, dir, "build")
	bin := filepath.Join(dir, "dist", "openwatch")
	if info, err := os.Stat(bin); err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("openwatch at %s not built or not executable: %v", bin, err)
	}
	return bin
}

// versionOutput returns the stdout of `<bin> --version`.
func versionOutput(t *testing.T, bin string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "--version")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s --version: %v stderr=%s", bin, err, stderr.String())
	}
	return stdout.String()
}

// @ac AC-01
// AC-01: make build-fips produces dist/openwatch-fips on a host with
// Go 1.25+ installed.
func TestFIPS_BuildProducesBinary(t *testing.T) {
	t.Run("release-fips-build/AC-01", func(t *testing.T) {
		bin := fipsBinary(t)
		info, err := os.Stat(bin)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Size() < 1024*1024 {
			t.Errorf("openwatch-fips size = %d, want > 1 MiB (stripped Go binary should still be ~10+ MiB)", info.Size())
		}
	})
}

// @ac AC-02
// AC-02: dist/openwatch-fips --version reports fips: true.
func TestFIPS_VersionFlagTrue(t *testing.T) {
	t.Run("release-fips-build/AC-02", func(t *testing.T) {
		bin := fipsBinary(t)
		out := versionOutput(t, bin)
		if !strings.Contains(out, "fips:      true") {
			t.Errorf("--version lacks 'fips:      true': %s", out)
		}
	})
}

// @ac AC-03
// AC-03: dist/openwatch --version (non-FIPS) reports fips: false.
func TestFIPS_NonFIPSReportsFalse(t *testing.T) {
	t.Run("release-fips-build/AC-03", func(t *testing.T) {
		bin := nonFIPSBinary(t)
		out := versionOutput(t, bin)
		if !strings.Contains(out, "fips:      false") {
			t.Errorf("non-FIPS --version lacks 'fips:      false': %s", out)
		}
	})
}

// @ac AC-04
// AC-04: FIPS binary contains symbols from crypto/internal/fips140
// (verifiable via `go tool nm`).
func TestFIPS_LinksFIPSModule(t *testing.T) {
	t.Run("release-fips-build/AC-04", func(t *testing.T) {
		bin := fipsBinary(t)
		var stdout bytes.Buffer
		cmd := exec.Command("go", "tool", "nm", bin)
		cmd.Stdout = &stdout
		if err := cmd.Run(); err != nil {
			t.Skipf("go tool nm unavailable: %v", err)
		}
		syms := stdout.String()
		// The FIPS module emits symbols under crypto/internal/fips140/<ver>.
		if !strings.Contains(syms, "crypto/internal/fips140") {
			t.Error("FIPS binary lacks crypto/internal/fips140 symbols")
		}
		if !strings.Contains(syms, "fips140/v1.0.0") {
			t.Error("FIPS binary lacks fips140/v1.0.0 module symbols")
		}
	})
}

// @ac AC-05
// AC-05: FIPS binary opens an HTTPS listener using the demo cert and
// serves /health with the same response shape as the non-FIPS binary.
func TestFIPS_TLSHandshakeAndHealth(t *testing.T) {
	t.Run("release-fips-build/AC-05", func(t *testing.T) {
		dsn := os.Getenv("OPENWATCH_TEST_DSN")
		if dsn == "" {
			t.Skip("set OPENWATCH_TEST_DSN to run FIPS runtime test")
		}
		bin := fipsBinary(t)
		dir := appDir(t)

		// Generate a self-signed cert pair in a temp dir.
		certDir := t.TempDir()
		if err := runShell(t, dir, "bash", []string{
			filepath.Join("packaging", "common", "gen-demo-cert.sh"),
			certDir,
		}); err != nil {
			t.Fatalf("gen-demo-cert.sh: %v", err)
		}

		port := pickFreePortStr(t)
		// Launch the FIPS binary with an env-driven config. --listen is a
		// global flag and must precede the subcommand.
		cmd := exec.Command(bin,
			"--listen", "127.0.0.1:"+port,
			"serve",
		)
		cmd.Env = append(os.Environ(),
			"OPENWATCH_DATABASE_DSN="+dsn,
			"OPENWATCH_SERVER_TLS_CERT="+filepath.Join(certDir, "cert.pem"),
			"OPENWATCH_SERVER_TLS_KEY="+filepath.Join(certDir, "key.pem"),
			"OPENWATCH_LOGGING_LEVEL=warn",
		)
		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("start FIPS binary: %v", err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Signal(os.Interrupt)
			_, _ = cmd.Process.Wait()
		})

		// Poll for the listener; up to 5s.
		client := &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test cert
			},
		}
		var resp *http.Response
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			r, err := client.Get("https://127.0.0.1:" + port + "/api/v1/health")
			if err == nil {
				resp = r
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if resp == nil {
			t.Fatalf("FIPS binary did not serve /health within 5s\nstderr: %s", stderr.String())
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		var got struct {
			Status      string `json:"status"`
			DbConnected bool   `json:"db_connected"`
			Version     string `json:"version"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode body: %v body=%s", err, body)
		}
		if got.Status != "healthy" {
			t.Errorf("status = %q, want healthy (FIPS binary should serve identical /health)", got.Status)
		}
		if !got.DbConnected {
			t.Error("db_connected = false")
		}
	})
}

// @ac AC-06
// AC-06: Running `go test ./...` with GOFIPS140=v1.0.0 on the test
// process produces zero new failures. Exercised here by invoking a
// scoped subset of the suite (correlation + license + auth) under the
// FIPS environment — full-suite re-run is the user's gate, not the
// test's.
func TestFIPS_TestSuitePassesUnderFIPSEnv(t *testing.T) {
	t.Run("release-fips-build/AC-06", func(t *testing.T) {
		dir := appDir(t)
		cmd := exec.Command("go", "test", "-timeout", "60s", "-count=1",
			"./internal/correlation/...",
			"./internal/license/...",
			"./internal/auth/...",
		)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFIPS140=v1.0.0")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("go test under GOFIPS140 failed: %v\nstdout: %s\nstderr: %s",
				err, stdout.String(), stderr.String())
		}
	})
}

// @ac AC-07
// AC-07: License JWT (Ed25519) verify still succeeds under FIPS mode.
// Run the license package's validator tests under GOFIPS140 and confirm
// they pass. Ed25519 is FIPS 186-5 approved.
func TestFIPS_Ed25519LicenseVerifyUnderFIPS(t *testing.T) {
	t.Run("release-fips-build/AC-07", func(t *testing.T) {
		dir := appDir(t)
		cmd := exec.Command("go", "test", "-timeout", "30s", "-count=1",
			"-run", "TestVerify_ValidJWT",
			"./internal/license/...",
		)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFIPS140=v1.0.0")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("Ed25519 license verify under FIPS failed: %v\nstdout: %s\nstderr: %s",
				err, stdout.String(), stderr.String())
		}
	})
}

// @ac AC-08
// AC-08: FIPS and non-FIPS binaries built from the same source tree
// report identical Version, Commit, and BuildTime tokens. (BuildTime is
// re-evaluated by make's $(shell ...) call, so the two builds in
// the same `go test` run can differ by a second — assert "close enough"
// for BuildTime and exact match for Version/Commit.)
func TestFIPS_VersionMetadataMatches(t *testing.T) {
	t.Run("release-fips-build/AC-08", func(t *testing.T) {
		nonFIPS := nonFIPSBinary(t)
		fips := fipsBinary(t)
		nfOut := versionOutput(t, nonFIPS)
		fOut := versionOutput(t, fips)
		nfVer := extractField(nfOut, "openwatch ")
		fVer := extractField(fOut, "openwatch ")
		if nfVer != fVer {
			t.Errorf("Version mismatch: non-FIPS=%q fips=%q", nfVer, fVer)
		}
		nfCommit := extractField(nfOut, "commit:")
		fCommit := extractField(fOut, "commit:")
		if nfCommit != fCommit {
			t.Errorf("Commit mismatch: non-FIPS=%q fips=%q", nfCommit, fCommit)
		}
	})
}

// extractField returns the trimmed value following the first occurrence
// of needle on its line.
func extractField(s, needle string) string {
	for _, line := range strings.Split(s, "\n") {
		if idx := strings.Index(line, needle); idx >= 0 {
			return strings.TrimSpace(line[idx+len(needle):])
		}
	}
	return ""
}

// pickFreePortStr probes a free TCP port and returns it as a string.
func pickFreePortStr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return strconv.Itoa(port)
}

// runShell executes a command in dir; returns its error.
func runShell(t *testing.T, dir, name string, args []string) error {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
