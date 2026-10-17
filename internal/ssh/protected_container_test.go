// @spec system-ssh-connectivity
//
// The protected dial against a real OpenSSH server whose PAM stack counts
// failed authentications with pam_faillock (deny = 3), in a disposable
// local container (testdata/sshd-faillock). What the host received is read
// from the account's failure tally, which is what locks an account.
//
// Opt-in: set OPENWATCH_SSH_CONTAINER_TESTS=1, with Docker available and
// OPENWATCH_TEST_DSN set. Hosted Go CI and the strict local gate set it.
// The account and passwords are synthetic.

package ssh

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/credprotect"
)

const sshdImage = "ow-sshd-faillock:test"

var buildSSHDImage = sync.OnceValue(func() error {
	out, err := exec.Command("docker", "build", "-q", "-t", sshdImage, "testdata/sshd-faillock").CombinedOutput()
	if err != nil {
		return errors.New(string(out))
	}
	return nil
})

// sshdContainer is one running test server.
type sshdContainer struct {
	t    *testing.T
	id   string
	port int
}

func startSSHD(t *testing.T, sshdArgs ...string) *sshdContainer {
	t.Helper()
	if os.Getenv("OPENWATCH_SSH_CONTAINER_TESTS") != "1" {
		t.Skip("set OPENWATCH_SSH_CONTAINER_TESTS=1 to run the sshd container tests")
	}
	if err := buildSSHDImage(); err != nil {
		t.Fatalf("build %s: %v", sshdImage, err)
	}
	// The container lives only while this process holds its stdin open.
	// Its main process starts sshd, waits for stdin to close, then stops
	// sshd; --rm then removes the container. The pipe's only writer is this
	// process, so the kernel closes it however the process ends, by
	// SIGTERM or SIGKILL included, which t.Cleanup cannot cover.
	cidfile := filepath.Join(t.TempDir(), "cid")
	args := append([]string{"run", "-i", "--rm", "--cidfile", cidfile, "-p", "127.0.0.1::22", sshdImage,
		"/bin/sh", "-c", `/usr/sbin/sshd -D -e "$@" & cat >/dev/null; kill $!; wait`, "sh"}, sshdArgs...)
	run := exec.Command("docker", args...)
	stdin, err := run.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := run.Start(); err != nil {
		t.Fatalf("docker run: %v", err)
	}
	c := &sshdContainer{t: t}
	t.Cleanup(func() {
		_ = stdin.Close()
		if c.id != "" {
			_ = exec.Command("docker", "rm", "-f", c.id).Run()
		}
		_ = run.Wait()
	})
	for deadline := time.Now().Add(30 * time.Second); ; {
		if b, err := os.ReadFile(cidfile); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			c.id = strings.TrimSpace(string(b))
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("docker run wrote no container id")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var out []byte
	out, err = exec.Command("docker", "port", c.id, "22/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	_, p, err := net.SplitHostPort(strings.TrimSpace(strings.Split(string(out), "\n")[0]))
	if err != nil {
		t.Fatalf("docker port %q: %v", out, err)
	}
	if c.port, err = strconv.Atoi(p); err != nil {
		t.Fatal(err)
	}
	// Wait for the banner, not just the published port.
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", p), time.Second)
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 4)
			n, _ := conn.Read(buf)
			_ = conn.Close()
			if n == 4 && string(buf) == "SSH-" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("sshd did not start")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return c
}

func (c *sshdContainer) exec(args ...string) string {
	c.t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", c.id}, args...)...).CombinedOutput()
	if err != nil {
		c.t.Fatalf("docker exec %v: %v: %s", args, err, out)
	}
	return string(out)
}

func (c *sshdContainer) setPassword(pw string) {
	c.t.Helper()
	c.exec("sh", "-c", "echo 'ops:"+pw+"' | chpasswd")
}

// failures is the account's pam_faillock tally: one line per failure
// recorded after the header.
func (c *sshdContainer) failures() int {
	c.t.Helper()
	n := 0
	for _, line := range strings.Split(c.exec("faillock", "--user", "ops"), "\n") {
		if f := strings.Fields(line); len(f) >= 4 && f[len(f)-1] == "V" {
			n++
		}
	}
	return n
}

// @ac AC-34
// AC-34: against OpenSSH with pam_faillock, a password rotated on the host
// and still held by OpenWatch leaves exactly one failure in the account's
// tally across concurrent workers and repeated dials, whichever password
// method the server offers, so an account that locks at three failures is
// never locked. The new password, entered and verified, then succeeds.
// Hosted Go CI runs it with OPENWATCH_SSH_CONTAINER_TESTS=1.
func TestProtectedDial_ContainerFaillockTally(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-34", func(t *testing.T) {
		for name, sshdArgs := range map[string][]string{
			"password and keyboard-interactive offered": nil,
			"keyboard-interactive only":                 {"-o", "PasswordAuthentication=no"},
		} {
			t.Run(name, func(t *testing.T) {
				c := startSSHD(t, sshdArgs...)
				f := newProtectedFixture(t, "ops")
				c.setPassword("P1")
				p1 := activePassword("ops", "P1")

				if _, err := protectedDial(t, "127.0.0.1", c.port, p1, f.opts(p1, credprotect.KindVerification)); err != nil {
					t.Fatalf("verification of P1: %v", err)
				}

				// The host rotates to P2. Eight workers dial at once with
				// P1, then five more dials follow.
				c.setPassword("P2")
				var wg sync.WaitGroup
				for range 8 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, _ = protectedDial(t, "127.0.0.1", c.port, p1, f.opts(p1, credprotect.KindOrdinary))
					}()
				}
				wg.Wait()
				for range 5 {
					if _, err := protectedDial(t, "127.0.0.1", c.port, p1, f.opts(p1, credprotect.KindOrdinary)); !errors.Is(err, credprotect.ErrBlocked) {
						t.Fatalf("a later dial with P1: %v, want ErrBlocked", err)
					}
				}
				if n := c.failures(); n != 1 {
					t.Fatalf("pam_faillock recorded %d failures for ops, want 1", n)
				}
				if m := f.mode(t, "P1"); m != credprotect.ModeBlocked {
					t.Fatalf("P1 is %s, want BLOCKED", m)
				}

				// The operator enters P2: a new secret, verified once.
				p2 := activePassword("ops", "P2")
				cl, res, err := ProtectedDial(context.Background(), "127.0.0.1", c.port, p2, f.opts(p2, credprotect.KindVerification))
				if err != nil {
					t.Fatalf("verification of P2: %v (outcome %s)", err, res.Outcome)
				}
				_ = cl.Close()
				// The login succeeding is the evidence the account never
				// locked: at deny = 3, a locked account refuses even the
				// right password. A success also clears the tally.
				if m := f.mode(t, "P2"); m != credprotect.ModeActive {
					t.Fatalf("P2 is %s, want ACTIVE", m)
				}
			})
		}
	})
}

// TestSSHDContainer_EndsWithTheTestProcess checks the teardown startSSHD
// relies on: a test process ended by a signal, which runs no t.Cleanup,
// still leaves no container running. A child test process starts the
// fixture and waits; the parent signals it and requires that container,
// by its id, to be gone.
func TestSSHDContainer_EndsWithTheTestProcess(t *testing.T) {
	if file := os.Getenv("OW_SSHD_LIFETIME_CHILD"); file != "" {
		c := startSSHD(t)
		if err := os.WriteFile(file, []byte(c.id), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Minute)
		return
	}
	if os.Getenv("OPENWATCH_SSH_CONTAINER_TESTS") != "1" {
		t.Skip("set OPENWATCH_SSH_CONTAINER_TESTS=1 to run the sshd container tests")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for name, sig := range map[string]os.Signal{"SIGTERM": syscall.SIGTERM, "SIGKILL": syscall.SIGKILL} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "id")
			child := exec.Command(exe, "-test.run=^TestSSHDContainer_EndsWithTheTestProcess$", "-test.timeout=5m")
			child.Env = append(os.Environ(), "OW_SSHD_LIFETIME_CHILD="+file)
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
			var id string
			for deadline := time.Now().Add(90 * time.Second); id == ""; {
				if b, err := os.ReadFile(file); err == nil {
					id = strings.TrimSpace(string(b))
				}
				if id == "" && time.Now().After(deadline) {
					t.Fatal("the child did not start its container")
				}
				time.Sleep(50 * time.Millisecond)
			}
			// Remove this container, and only it, if the teardown fails.
			defer func() { _ = exec.Command("docker", "rm", "-f", id).Run() }()
			if !containerExists(id) {
				t.Fatal("the container was not running before the signal")
			}
			if err := child.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			_ = child.Wait()
			for deadline := time.Now().Add(20 * time.Second); containerExists(id); {
				if time.Now().After(deadline) {
					t.Fatalf("container %s is still there 20s after %s ended the test process", id, name)
				}
				time.Sleep(200 * time.Millisecond)
			}
		})
	}
}

// containerExists reports whether docker still knows the container.
func containerExists(id string) bool {
	return exec.Command("docker", "inspect", "--format", "{{.Id}}", id).Run() == nil
}
