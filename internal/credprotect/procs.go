package credprotect

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LocalProcesses checks processes on this Linux machine through /proc. A
// process is the same process only if its PID and its start time (field 22
// of /proc/PID/stat, in clock ticks since boot) both match, so a reused PID
// is not mistaken for the owner.
type LocalProcesses struct{}

// Machine is /etc/machine-id, or the hostname when that is unreadable.
func (LocalProcesses) Machine() string {
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id
		}
	}
	h, _ := os.Hostname()
	return "host:" + h
}

// Alive reports whether a process with this PID and start time exists.
func (LocalProcesses) Alive(pid int, start string) (bool, error) {
	got, err := processStart(pid)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return got == start, nil
}

// processStart reads a process's start time from /proc/PID/stat.
func processStart(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	return parseStart(string(b))
}

// parseStart returns field 22 of a /proc/PID/stat line. The command name,
// field 2, is in parentheses and may contain spaces and parentheses, so
// fields are counted from the last ')'.
func parseStart(s string) (string, error) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return "", errors.New("credprotect: unreadable process stat")
	}
	fields := strings.Fields(s[i+1:])
	// fields[0] is field 3 (state); field 22 is fields[19].
	if len(fields) < 20 {
		return "", errors.New("credprotect: short process stat")
	}
	return fields[19], nil
}

// SelfOwner is this process as a reservation owner.
func SelfOwner() (Owner, error) {
	pid := os.Getpid()
	start, err := processStart(pid)
	if err != nil {
		return Owner{}, fmt.Errorf("credprotect: own start time: %w", err)
	}
	return Owner{Machine: LocalProcesses{}.Machine(), PID: pid, Start: start}, nil
}
