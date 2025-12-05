package runtime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// PodmanRuntime implements the Runtime interface for Podman
type PodmanRuntime struct{}

// NewPodmanRuntime creates a new Podman runtime instance
func NewPodmanRuntime() *PodmanRuntime {
	return &PodmanRuntime{}
}

// Name returns the runtime name
func (p *PodmanRuntime) Name() string {
	return "Podman"
}

// IsAvailable checks if Podman is installed and available
func (p *PodmanRuntime) IsAvailable() bool {
	if !isCommandAvailable("podman") {
		return false
	}

	// Also check for podman-compose
	return isCommandAvailable("podman-compose")
}

// ComposeCommand returns the compose command for Podman
func (p *PodmanRuntime) ComposeCommand() string {
	return "podman-compose"
}

// Start starts the containers using Podman
func (p *PodmanRuntime) Start(ctx context.Context, options StartOptions) error {
	args := []string{}

	// Add compose file if specified
	if options.ComposeFile != "" {
		args = append(args, "-f", options.ComposeFile)
	} else if options.Environment == "dev" {
		// Check if dev compose file exists
		if _, err := os.Stat("podman-compose.dev.yml"); err == nil {
			args = append(args, "-f", "podman-compose.dev.yml")
		} else if _, err := os.Stat("docker-compose.dev.yml"); err == nil {
			args = append(args, "-f", "docker-compose.dev.yml")
		} else {
			args = append(args, "-f", "podman-compose.yml")
		}
	} else {
		// Use podman-compose.yml if it exists, otherwise fall back to docker-compose.yml
		if _, err := os.Stat("podman-compose.yml"); err == nil {
			args = append(args, "-f", "podman-compose.yml")
		} else {
			args = append(args, "-f", "docker-compose.yml")
		}
	}

	args = append(args, "up")

	if options.Detach {
		args = append(args, "-d")
	}

	if options.Build {
		args = append(args, "--build")
	}

	if options.ForceRecreate {
		args = append(args, "--force-recreate")
	}

	// Execute the command
	cmd := exec.CommandContext(ctx, "podman-compose", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Stop stops the containers using Podman
func (p *PodmanRuntime) Stop(ctx context.Context, options StopOptions) error {
	args := []string{"down"}

	if options.RemoveVolumes {
		args = append(args, "-v")
	}

	// Execute the command
	cmd := exec.CommandContext(ctx, "podman-compose", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Status returns the status of Podman containers
func (p *PodmanRuntime) Status(ctx context.Context) (*StatusInfo, error) {
	// Get container status using podman-compose ps
	output, err := execCommandOutput(ctx, "podman-compose", "ps")
	if err != nil {
		return nil, fmt.Errorf("failed to get container status: %w", err)
	}

	// For now, return a simple status
	// TODO: Parse output for detailed status
	status := &StatusInfo{
		Overall: "Running",
		Services: []ServiceStatus{},
	}

	// Simple check if containers are running
	if output == "" {
		status.Overall = "Stopped"
	}

	return status, nil
}

// Logs returns logs from a specific service
func (p *PodmanRuntime) Logs(ctx context.Context, service string, options LogOptions) error {
	args := []string{"logs"}

	if options.Follow {
		args = append(args, "-f")
	}

	if options.Tail != "" {
		args = append(args, "--tail", options.Tail)
	}

	if options.Timestamps {
		args = append(args, "-t")
	}

	args = append(args, service)

	// Execute the command
	cmd := exec.CommandContext(ctx, "podman-compose", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Exec executes a command in a Podman container
func (p *PodmanRuntime) Exec(ctx context.Context, service string, command []string) error {
	args := []string{"exec", service}
	args = append(args, command...)

	// Execute the command
	cmd := exec.CommandContext(ctx, "podman-compose", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
