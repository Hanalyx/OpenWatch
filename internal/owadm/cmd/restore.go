// Restore command - included in all builds (native + container)

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	restoreDBOnly     bool
	restoreConfigOnly bool
	restoreForce      bool
)

var restoreCmd = &cobra.Command{
	Use:   "restore <backup-file>",
	Short: "Restore OpenWatch from a backup",
	Long: `Restore OpenWatch database and configuration from a backup archive.

The restore process:
  1. Extracts the backup archive
  2. Restores PostgreSQL database (drops and recreates)
  3. Restores configuration files to /etc/openwatch/

WARNING: This will overwrite existing data. Make sure to stop OpenWatch services first.

Examples:
  owadm restore openwatch-backup-20240101.tar.gz    # Full restore
  owadm restore --db-only backup.tar.gz             # Restore database only
  owadm restore --config-only backup.tar.gz         # Restore config only
  owadm restore --force backup.tar.gz               # Skip confirmation`,
	Args: cobra.ExactArgs(1),
	RunE: runRestore,
}

func init() {
	rootCmd.AddCommand(restoreCmd)

	restoreCmd.Flags().BoolVar(&restoreDBOnly, "db-only", false, "Restore database only")
	restoreCmd.Flags().BoolVar(&restoreConfigOnly, "config-only", false, "Restore configuration only")
	restoreCmd.Flags().BoolVar(&restoreForce, "force", false, "Skip confirmation prompt")
}

func runRestore(cmd *cobra.Command, args []string) error {
	backupFile := args[0]

	PrintHeader("OpenWatch Restore")

	// Verify backup file exists
	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", backupFile)
	}

	// Confirmation prompt
	if !restoreForce {
		LogWarning("This will overwrite existing data!")
		fmt.Print("Are you sure you want to continue? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			LogInfo("Restore cancelled")
			return nil
		}
	}

	// Create temporary directory for extraction
	tempDir, err := os.MkdirTemp("", "owadm-restore-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Extract backup archive
	LogInfo("Extracting backup archive...")
	if err := extractTarArchive(backupFile, tempDir); err != nil {
		return fmt.Errorf("failed to extract backup: %w", err)
	}
	LogSuccess("Archive extracted")

	// Restore database
	if !restoreConfigOnly {
		dbDumpPath := filepath.Join(tempDir, "database.sql")
		if _, err := os.Stat(dbDumpPath); err == nil {
			LogInfo("Restoring database...")
			if err := restoreDatabase(dbDumpPath); err != nil {
				LogWarning(fmt.Sprintf("Database restore failed: %v", err))
				if restoreDBOnly {
					return fmt.Errorf("database restore failed: %w", err)
				}
				LogInfo("Continuing with configuration restore...")
			} else {
				LogSuccess("Database restored")
			}
		} else {
			LogWarning("No database dump found in backup")
		}
	}

	// Restore configuration
	if !restoreDBOnly {
		configBackupDir := filepath.Join(tempDir, "config")
		if _, err := os.Stat(configBackupDir); err == nil {
			LogInfo("Restoring configuration...")
			if err := restoreConfig(configBackupDir); err != nil {
				return fmt.Errorf("configuration restore failed: %w", err)
			}
			LogSuccess("Configuration restored")
		} else {
			LogWarning("No configuration found in backup")
		}
	}

	fmt.Println()
	LogSuccess("Restore complete!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Review configuration: cat /etc/openwatch/ow.yml")
	fmt.Println("  2. Start services: systemctl start openwatch.target")
	fmt.Println("  3. Verify health: owadm health")

	return nil
}

func extractTarArchive(archivePath, destDir string) error {
	// Detect if gzipped
	var cmd *exec.Cmd
	if filepath.Ext(archivePath) == ".gz" || filepath.Ext(filepath.Base(archivePath[:len(archivePath)-3])) == ".tar" {
		cmd = exec.Command("tar", "-xzf", archivePath, "-C", destDir)
	} else {
		cmd = exec.Command("tar", "-xf", archivePath, "-C", destDir)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tar extraction failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

func restoreDatabase(dumpPath string) error {
	dbHost := getEnvOrDefault("OPENWATCH_DATABASE_HOST", "localhost")
	dbPort := getEnvOrDefault("OPENWATCH_DATABASE_PORT", "5432")
	dbName := getEnvOrDefault("OPENWATCH_DATABASE_NAME", "openwatch")
	dbUser := getEnvOrDefault("OPENWATCH_DATABASE_USER", "openwatch")
	dbPass := os.Getenv("OPENWATCH_DATABASE_PASSWORD")

	env := os.Environ()
	if dbPass != "" {
		env = append(env, fmt.Sprintf("PGPASSWORD=%s", dbPass))
	}

	// Drop and recreate database
	LogVerbose("Dropping existing database...")
	dropCmd := exec.Command("psql",
		"-h", dbHost, "-p", dbPort, "-U", dbUser, "-d", "postgres",
		"-c", fmt.Sprintf("DROP DATABASE IF EXISTS %s", dbName))
	dropCmd.Env = env
	dropCmd.Run() // Ignore errors - database might not exist

	LogVerbose("Creating database...")
	createCmd := exec.Command("psql",
		"-h", dbHost, "-p", dbPort, "-U", dbUser, "-d", "postgres",
		"-c", fmt.Sprintf("CREATE DATABASE %s OWNER %s", dbName, dbUser))
	createCmd.Env = env
	if output, err := createCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create database: %w\nOutput: %s", err, string(output))
	}

	// Restore from dump
	LogVerbose("Restoring database from dump...")
	restoreCmd := exec.Command("psql",
		"-h", dbHost, "-p", dbPort, "-U", dbUser, "-d", dbName,
		"-f", dumpPath)
	restoreCmd.Env = env

	output, err := restoreCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restore database: %w\nOutput: %s", err, string(output))
	}

	return nil
}

func restoreConfig(configBackupDir string) error {
	destDir := "/etc/openwatch"

	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destDir, 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Copy all files from backup
	entries, err := os.ReadDir(configBackupDir)
	if err != nil {
		return fmt.Errorf("failed to read config backup: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		src := filepath.Join(configBackupDir, entry.Name())
		dst := filepath.Join(destDir, entry.Name())

		if err := copyFile(src, dst); err != nil {
			LogWarning(fmt.Sprintf("Could not restore %s: %v", entry.Name(), err))
		} else {
			LogVerbose(fmt.Sprintf("Restored: %s", entry.Name()))
		}
	}

	// Set proper permissions on secrets
	secretsPath := filepath.Join(destDir, "secrets.env")
	if _, err := os.Stat(secretsPath); err == nil {
		os.Chmod(secretsPath, 0600)
	}

	privatKeyPath := filepath.Join(destDir, "jwt_private.pem")
	if _, err := os.Stat(privatKeyPath); err == nil {
		os.Chmod(privatKeyPath, 0600)
	}

	return nil
}
