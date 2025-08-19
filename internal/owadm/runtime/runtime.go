package runtime

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runtime represents a container runtime interface
type Runtime interface {
	// Name returns the runtime name
	Name() string
	
	// IsAvailable checks if the runtime is installed and available
	IsAvailable() bool
	
	// Start starts the containers
	Start(ctx context.Context, options StartOptions) error
	
	// Stop stops the containers
	Stop(ctx context.Context, options StopOptions) error
	
	// Status returns the status of containers
	Status(ctx context.Context) (*StatusInfo, error)
	
	// Logs returns logs from a specific service
	Logs(ctx context.Context, service string, options LogOptions) error
	
	// Exec executes a command in a container
	Exec(ctx context.Context, service string, command []string) error
	
	// ComposeCommand returns the compose command for this runtime
	ComposeCommand() string
}

// StartOptions contains options for starting containers
type StartOptions struct {
	Detach      bool
	Build       bool
	ForceRecreate bool
	Environment string
	ComposeFile string
	Timeout     time.Duration
}

// StopOptions contains options for stopping containers
type StopOptions struct {
	Force       bool
	Timeout     time.Duration
	RemoveVolumes bool
}

// LogOptions contains options for viewing logs
type LogOptions struct {
	Follow    bool
	Tail      string
	Since     string
	Timestamps bool
}

// StatusInfo contains container status information
type StatusInfo struct {
	Services []ServiceStatus
	Overall  string
}

// ServiceStatus represents the status of a single service
type ServiceStatus struct {
	Name      string
	State     string
	Health    string
	Uptime    string
	Ports     []string
	Image     string
}

// DetectRuntime automatically detects the available container runtime
func DetectRuntime() (Runtime, error) {
	// Try Podman first (preferred for rootless operations)
	if podman := NewPodmanRuntime(); podman.IsAvailable() {
		return podman, nil
	}
	
	// Fall back to Docker
	if docker := NewDockerRuntime(); docker.IsAvailable() {
		return docker, nil
	}
	
	return nil, fmt.Errorf("no container runtime found. Please install Docker or Podman")
}

// GetRuntime returns a specific runtime by name
func GetRuntime(name string) (Runtime, error) {
	switch strings.ToLower(name) {
	case "docker":
		runtime := NewDockerRuntime()
		if !runtime.IsAvailable() {
			return nil, fmt.Errorf("Docker is not available")
		}
		return runtime, nil
		
	case "podman":
		runtime := NewPodmanRuntime()
		if !runtime.IsAvailable() {
			return nil, fmt.Errorf("Podman is not available")
		}
		return runtime, nil
		
	default:
		return nil, fmt.Errorf("unknown runtime: %s", name)
	}
}

// execCommand is a helper to execute shell commands
func execCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

// execCommandOutput executes a command and returns its output
func execCommandOutput(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// isCommandAvailable checks if a command is available in PATH
func isCommandAvailable(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}