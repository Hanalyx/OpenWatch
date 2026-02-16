//go:build !container

package utils

import (
	"fmt"
	"os"
	"os/exec"
)

// CheckPrerequisites checks if all required tools and conditions are met for native installation
func CheckPrerequisites() error {
	// Check for systemctl (systemd)
	if !isCommandAvailable("systemctl") {
		return fmt.Errorf("systemctl not found. OpenWatch native requires systemd")
	}

	// Check for openssl (for key generation)
	if !isCommandAvailable("openssl") {
		return fmt.Errorf("openssl not found. Please install openssl for security key generation")
	}

	return nil
}

// isCommandAvailable checks if a command exists in PATH
func isCommandAvailable(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// CheckConfigFile checks if the OpenWatch configuration file exists
func CheckConfigFile() error {
	configPath := "/etc/openwatch/ow.yml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file not found: %s", configPath)
	}
	return nil
}

// CheckSecretsFile checks if the secrets file exists with correct permissions
func CheckSecretsFile() error {
	secretsPath := "/etc/openwatch/secrets.env"
	info, err := os.Stat(secretsPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("secrets file not found: %s", secretsPath)
	}
	if err != nil {
		return fmt.Errorf("cannot access secrets file: %w", err)
	}

	// Check permissions (should be 0600)
	mode := info.Mode().Perm()
	if mode != 0600 {
		return fmt.Errorf("secrets file has insecure permissions: %o (should be 600)", mode)
	}

	return nil
}

// CheckSystemdServices checks if OpenWatch systemd services are installed
func CheckSystemdServices() error {
	services := []string{
		"openwatch-api.service",
		"openwatch-worker@.service",
		"openwatch-beat.service",
	}

	for _, service := range services {
		servicePath := fmt.Sprintf("/lib/systemd/system/%s", service)
		if _, err := os.Stat(servicePath); os.IsNotExist(err) {
			return fmt.Errorf("systemd service not found: %s", service)
		}
	}

	return nil
}
