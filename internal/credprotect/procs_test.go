// @spec system-credential-protection

package credprotect

import (
	"os"
	"os/exec"
	"testing"
)

// @ac AC-08
// AC-08: verified termination needs the PID and the start time together.
func TestLocalProcesses(t *testing.T) {
	t.Run("system-credential-protection/AC-08", func(t *testing.T) {
		if _, err := os.Stat("/proc/self/stat"); err != nil {
			t.Skip("needs /proc")
		}
		self, err := SelfOwner()
		if err != nil {
			t.Fatal(err)
		}
		p := LocalProcesses{}
		if self.Machine == "" || self.Machine != p.Machine() {
			t.Fatalf("machine %q, want %q", self.Machine, p.Machine())
		}
		if alive, err := p.Alive(self.PID, self.Start); err != nil || !alive {
			t.Fatalf("this process is not alive: %v, %v", alive, err)
		}
		if alive, _ := p.Alive(self.PID, self.Start+"0"); alive {
			t.Fatal("a reused PID with another start time counted as the owner")
		}
		// A process that has exited and been reaped.
		cmd := exec.Command("true")
		if err := cmd.Run(); err != nil {
			t.Skip("needs the true command")
		}
		if alive, err := p.Alive(cmd.Process.Pid, "1"); err != nil || alive {
			t.Fatalf("an exited process is alive: %v, %v", alive, err)
		}
	})
}

// A command name with spaces and parentheses must not shift the fields.
func TestProcessStartParsesAroundTheCommandName(t *testing.T) {
	stat := "1234 (a ) b (c)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 19 20"
	got, err := parseStart(stat)
	if err != nil || got != "777" {
		t.Fatalf("start = %q, %v; want 777", got, err)
	}
}
