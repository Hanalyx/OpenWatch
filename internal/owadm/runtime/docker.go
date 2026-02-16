//go:build container

package runtime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DockerRuntime implements the Runtime interface for Docker
type DockerRuntime struct {
	composeCommand string
}

// NewDockerRuntime creates a new Docker runtime instance
func NewDockerRuntime() *DockerRuntime {
	// Detect docker-compose vs docker compose
	composeCmd := "docker-compose"
	if !isCommandAvailable("docker-compose") {
		// Try new docker compose plugin
		ctx := context.Background()
		if output, err := execCommandOutput(ctx, "docker", "compose", "version"); err == nil && strings.Contains(output, "Docker Compose") {
			composeCmd = "docker compose"
		}
	}

	return &DockerRuntime{
		composeCommand: composeCmd,
	}
}

// Name returns the runtime name
func (d *DockerRuntime) Name() string {
	return "Docker"
}

// IsAvailable checks if Docker is installed and available
func (d *DockerRuntime) IsAvailable() bool {
	if !isCommandAvailable("docker") {
		return false
	}

	// Check if Docker daemon is running
	ctx := context.Background()
	err := execCommand(ctx, "docker", "info")
	return err == nil
}

// ComposeCommand returns the compose command for Docker
func (d *DockerRuntime) ComposeCommand() string {
	return d.composeCommand
}

// Start starts the containers using Docker
func (d *DockerRuntime) Start(ctx context.Context, options StartOptions) error {
	args := []string{}

	// Handle docker compose vs docker-compose
	if d.composeCommand == "docker compose" {
		args = append(args, "compose")
	}

	// Add compose file if specified
	if options.ComposeFile != "" {
		args = append(args, "-f", options.ComposeFile)
	} else if options.Environment == "dev" {
		args = append(args, "-f", "docker-compose.dev.yml")
	} else {
		args = append(args, "-f", "docker-compose.yml")
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
	var cmd *exec.Cmd
	if d.composeCommand == "docker compose" {
		cmd = exec.CommandContext(ctx, "docker", args...)
	} else {
		cmd = exec.CommandContext(ctx, "docker-compose", args[2:]...) // Skip "compose" part
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Stop stops the containers using Docker
func (d *DockerRuntime) Stop(ctx context.Context, options StopOptions) error {
	args := []string{}

	if d.composeCommand == "docker compose" {
		args = append(args, "compose")
	}

	args = append(args, "down")

	if options.RemoveVolumes {
		args = append(args, "-v")
	}

	// Execute the command
	var cmd *exec.Cmd
	if d.composeCommand == "docker compose" {
		cmd = exec.CommandContext(ctx, "docker", args...)
	} else {
		cmd = exec.CommandContext(ctx, "docker-compose", args[2:]...)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Status returns the status of Docker containers
func (d *DockerRuntime) Status(ctx context.Context) (*StatusInfo, error) {
	args := []string{}

	if d.composeCommand == "docker compose" {
		args = append(args, "compose", "ps", "--format", "json")
	} else {
		args = []string{"ps", "--format", "json"}
	}

	var output string
	var err error

	if d.composeCommand == "docker compose" {
		output, err = execCommandOutput(ctx, "docker", args...)
	} else {
		output, err = execCommandOutput(ctx, "docker-compose", args...)
	}

	// Use output to prevent compilation error
	_ = output

	if err != nil {
		return nil, fmt.Errorf("failed to get container status: %w", err)
	}

	// For now, return a simple status
	// TODO: Parse JSON output for detailed status
	status := &StatusInfo{
		Overall: "Running",
		Services: []ServiceStatus{},
	}

	return status, nil
}

// Logs returns logs from a specific service
func (d *DockerRuntime) Logs(ctx context.Context, service string, options LogOptions) error {
	args := []string{}

	if d.composeCommand == "docker compose" {
		args = append(args, "compose")
	}

	args = append(args, "logs")

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
	var cmd *exec.Cmd
	if d.composeCommand == "docker compose" {
		cmd = exec.CommandContext(ctx, "docker", args...)
	} else {
		cmd = exec.CommandContext(ctx, "docker-compose", args[2:]...)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Exec executes a command in a Docker container
func (d *DockerRuntime) Exec(ctx context.Context, service string, command []string) error {
	args := []string{}

	if d.composeCommand == "docker compose" {
		args = append(args, "compose")
	}

	args = append(args, "exec", service)
	args = append(args, command...)

	// Execute the command
	var cmd *exec.Cmd
	if d.composeCommand == "docker compose" {
		cmd = exec.CommandContext(ctx, "docker", args...)
	} else {
		cmd = exec.CommandContext(ctx, "docker-compose", args[2:]...)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
