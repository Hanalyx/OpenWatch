package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Config represents the OpenWatch configuration structure
type Config struct {
	Runtime struct {
		Engine   string `yaml:"engine"`
		Rootless bool   `yaml:"rootless"`
	} `yaml:"runtime"`
	Database struct {
		Host    string `yaml:"host"`
		Port    int    `yaml:"port"`
		SSLMode string `yaml:"ssl_mode"`
	} `yaml:"database"`
	Web struct {
		Port int `yaml:"port"`
		SSL  struct {
			Enabled bool   `yaml:"enabled"`
			Cert    string `yaml:"cert_path"`
			Key     string `yaml:"key_path"`
		} `yaml:"ssl"`
	} `yaml:"web"`
	Scanning struct {
		SSHKeyPath      string `yaml:"ssh_key_path"`
		ConcurrentScans int    `yaml:"concurrent_scans"`
	} `yaml:"scanning"`
	Security struct {
		FIPSMode bool `yaml:"fips_mode"`
	} `yaml:"security"`
}

var (
	databaseOnly bool
	showDefaults bool
)

var validateConfigCmd = &cobra.Command{
	Use:   "validate-config",
	Short: "Validate OpenWatch configuration",
	Long:  `Validate the OpenWatch configuration file and check for common issues.`,
	RunE:  runValidateConfig,
}

func init() {
	validateConfigCmd.Flags().BoolVar(&databaseOnly, "database-only", false, "Only validate database configuration")
	validateConfigCmd.Flags().BoolVar(&showDefaults, "show-defaults", false, "Show default values for all settings")
	validateConfigCmd.Flags().StringVar(&configPath, "config", "/etc/openwatch/ow.yml", "Path to configuration file")
}

func runValidateConfig(cmd *cobra.Command, args []string) error {
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file not found: %s", configPath)
	}

	// Read configuration file
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read configuration: %v", err)
	}

	// Parse YAML with environment variable substitution
	expandedData := os.ExpandEnv(string(data))

	var config Config
	if err := yaml.Unmarshal([]byte(expandedData), &config); err != nil {
		return fmt.Errorf("invalid YAML configuration: %v", err)
	}

	fmt.Printf("%s Configuration validation for: %s\n\n", blue("[INFO]"), configPath)

	// Validate based on flags
	if databaseOnly {
		return validateDatabase(config)
	}

	// Full validation
	var errors []string
	var warnings []string

	// Runtime validation
	fmt.Printf("%s Runtime configuration\n", bold("Runtime:"))
	if err := validateRuntime(config); err != nil {
		errors = append(errors, err.Error())
		fmt.Printf("  %s %s\n", red("ERROR:"), err.Error())
	} else {
		fmt.Printf("  %s Container runtime: %s\n", green("OK:"), config.Runtime.Engine)
		fmt.Printf("  %s Rootless mode: %v\n", green("OK:"), config.Runtime.Rootless)
	}

	// Database validation
	fmt.Printf("\n%s Database configuration\n", bold("Database:"))
	if err := validateDatabaseConfig(config); err != nil {
		errors = append(errors, err.Error())
		fmt.Printf("  %s %s\n", red("ERROR:"), err.Error())
	} else {
		fmt.Printf("  %s PostgreSQL: %s:%d\n", green("OK:"), config.Database.Host, config.Database.Port)
		fmt.Printf("  %s SSL mode: %s\n", green("OK:"), config.Database.SSLMode)
	}

	// Web configuration
	fmt.Printf("\n%s Web interface\n", bold("Web:"))
	if config.Web.Port < 1 || config.Web.Port > 65535 {
		errors = append(errors, fmt.Sprintf("invalid web port: %d", config.Web.Port))
		fmt.Printf("  %s Invalid port: %d\n", red("ERROR:"), config.Web.Port)
	} else {
		fmt.Printf("  %s Port: %d\n", green("OK:"), config.Web.Port)
	}

	if config.Web.SSL.Enabled {
		if _, err := os.Stat(config.Web.SSL.Cert); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("SSL certificate not found: %s", config.Web.SSL.Cert))
			fmt.Printf("  %s SSL certificate not found: %s\n", yellow("WARNING:"), config.Web.SSL.Cert)
		}
		if _, err := os.Stat(config.Web.SSL.Key); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("SSL key not found: %s", config.Web.SSL.Key))
			fmt.Printf("  %s SSL key not found: %s\n", yellow("WARNING:"), config.Web.SSL.Key)
		}
	} else {
		warnings = append(warnings, "SSL is disabled - not recommended for production")
		fmt.Printf("  %s SSL disabled (not recommended for production)\n", yellow("WARNING:"))
	}

	// Scanning configuration
	fmt.Printf("\n%s Scanning configuration\n", bold("Scanning:"))
	if config.Scanning.SSHKeyPath != "" {
		if _, err := os.Stat(config.Scanning.SSHKeyPath); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("SSH key not found: %s", config.Scanning.SSHKeyPath))
			fmt.Printf("  %s SSH key not found: %s\n", yellow("WARNING:"), config.Scanning.SSHKeyPath)
		} else {
			// Check SSH key permissions
			info, _ := os.Stat(config.Scanning.SSHKeyPath)
			mode := info.Mode()
			if mode.Perm() != 0600 && mode.Perm() != 0400 {
				warnings = append(warnings, fmt.Sprintf("SSH key has insecure permissions: %v", mode.Perm()))
				fmt.Printf("  %s SSH key has insecure permissions: %v (should be 600)\n", yellow("WARNING:"), mode.Perm())
			} else {
				fmt.Printf("  %s SSH key: %s\n", green("OK:"), config.Scanning.SSHKeyPath)
			}
		}
	}
	fmt.Printf("  %s Concurrent scans: %d\n", green("OK:"), config.Scanning.ConcurrentScans)

	// Security settings
	fmt.Printf("\n%s Security settings\n", bold("Security:"))
	if config.Security.FIPSMode {
		fmt.Printf("  %s FIPS mode: enabled\n", green("OK:"))
	} else {
		fmt.Printf("  %s FIPS mode: disabled\n", blue("INFO:"))
	}

	// Check secrets file
	fmt.Printf("\n%s Secrets configuration\n", bold("Secrets:"))
	secretsPath := filepath.Join(filepath.Dir(configPath), "secrets.env")
	if _, err := os.Stat(secretsPath); os.IsNotExist(err) {
		errors = append(errors, "secrets.env file not found")
		fmt.Printf("  %s Secrets file not found: %s\n", red("ERROR:"), secretsPath)
	} else {
		// Check permissions
		info, _ := os.Stat(secretsPath)
		mode := info.Mode()
		if mode.Perm() != 0600 {
			errors = append(errors, fmt.Sprintf("secrets.env has insecure permissions: %v", mode.Perm()))
			fmt.Printf("  %s Insecure permissions on secrets.env: %v (must be 600)\n", red("ERROR:"), mode.Perm())
		} else {
			fmt.Printf("  %s Secrets file found with correct permissions\n", green("OK:"))
		}

		// Check for default passwords
		content, _ := ioutil.ReadFile(secretsPath)
		if strings.Contains(string(content), "CHANGEME") {
			errors = append(errors, "default passwords detected in secrets.env")
			fmt.Printf("  %s Default passwords detected - run generate-secrets.sh\n", red("ERROR:"))
		}
	}

	// Summary
	fmt.Printf("\n%s\n", strings.Repeat("─", 60))
	if len(errors) > 0 {
		fmt.Printf("\n%s Configuration validation FAILED\n", red("ERROR:"))
		fmt.Printf("\nErrors found:\n")
		for _, err := range errors {
			fmt.Printf("  - %s\n", err)
		}
	} else {
		fmt.Printf("\n%s Configuration validation PASSED\n", green("OK:"))
	}

	if len(warnings) > 0 {
		fmt.Printf("\nWarnings:\n")
		for _, warn := range warnings {
			fmt.Printf("  - %s\n", warn)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed")
	}

	return nil
}

func validateRuntime(config Config) error {
	validEngines := []string{"auto", "docker", "podman"}
	for _, engine := range validEngines {
		if config.Runtime.Engine == engine {
			// If specific runtime requested, check if it's available
			if engine != "auto" {
				if _, err := exec.LookPath(engine); err != nil {
					return fmt.Errorf("runtime '%s' not found in PATH", engine)
				}
			}
			return nil
		}
	}
	return fmt.Errorf("invalid runtime engine: %s (must be auto, docker, or podman)", config.Runtime.Engine)
}

func validateDatabase(config Config) error {
	fmt.Printf("%s Validating database configuration...\n\n", blue("[INFO]"))

	if err := validateDatabaseConfig(config); err != nil {
		fmt.Printf("%s Database validation failed: %v\n", red("ERROR:"), err)
		return err
	}

	fmt.Printf("%s Database configuration is valid\n", green("OK:"))
	fmt.Printf("  Host: %s:%d\n", config.Database.Host, config.Database.Port)
	fmt.Printf("  SSL: %s\n", config.Database.SSLMode)

	return nil
}

func validateDatabaseConfig(config Config) error {
	if config.Database.Host == "" {
		return fmt.Errorf("database host is not configured")
	}

	if config.Database.Port < 1 || config.Database.Port > 65535 {
		return fmt.Errorf("invalid database port: %d", config.Database.Port)
	}

	validSSLModes := []string{"disable", "prefer", "require", "verify-ca", "verify-full"}
	validMode := false
	for _, mode := range validSSLModes {
		if config.Database.SSLMode == mode {
			validMode = true
			break
		}
	}
	if !validMode {
		return fmt.Errorf("invalid database SSL mode: %s", config.Database.SSLMode)
	}

	return nil
}
