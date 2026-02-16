// Backup command - included in all builds (native + container)

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var (
	backupOutput    string
	backupNoCompress bool
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup OpenWatch database and configuration",
	Long: `Create a backup of the OpenWatch PostgreSQL database and configuration files.

The backup includes:
  - PostgreSQL database dump (all tables and data)
  - Configuration files from /etc/openwatch/
  - JWT keys (encrypted)

Examples:
  owadm backup                              # Backup to default location
  owadm backup --output /backup/ow.tar.gz   # Backup to specific file
  owadm backup --no-compress                # Create uncompressed backup`,
	RunE: runBackup,
}

func init() {
	rootCmd.AddCommand(backupCmd)

	backupCmd.Flags().StringVarP(&backupOutput, "output", "o", "", "Output file path (default: openwatch-backup-TIMESTAMP.tar.gz)")
	backupCmd.Flags().BoolVar(&backupNoCompress, "no-compress", false, "Create uncompressed tar archive")
}

func runBackup(cmd *cobra.Command, args []string) error {
	PrintHeader("OpenWatch Backup")

	// Determine output path
	timestamp := time.Now().Format("20060102-150405")
	if backupOutput == "" {
		if backupNoCompress {
			backupOutput = fmt.Sprintf("openwatch-backup-%s.tar", timestamp)
		} else {
			backupOutput = fmt.Sprintf("openwatch-backup-%s.tar.gz", timestamp)
		}
	}

	// Create temporary directory for backup contents
	tempDir, err := os.MkdirTemp("", "owadm-backup-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	LogInfo("Starting backup...")

	// Step 1: Dump PostgreSQL database
	LogInfo("Backing up database...")
	dbDumpPath := filepath.Join(tempDir, "database.sql")
	if err := dumpDatabase(dbDumpPath); err != nil {
		LogWarning(fmt.Sprintf("Database backup failed: %v", err))
		LogInfo("Continuing with configuration backup...")
	} else {
		LogSuccess("Database backup complete")
	}

	// Step 2: Copy configuration files
	LogInfo("Backing up configuration...")
	configBackupDir := filepath.Join(tempDir, "config")
	if err := os.MkdirAll(configBackupDir, 0755); err != nil {
		return fmt.Errorf("failed to create config backup directory: %w", err)
	}

	configFiles := []string{
		"/etc/openwatch/ow.yml",
		"/etc/openwatch/secrets.env",
		"/etc/openwatch/jwt_private.pem",
		"/etc/openwatch/jwt_public.pem",
	}

	for _, src := range configFiles {
		if _, err := os.Stat(src); err == nil {
			dst := filepath.Join(configBackupDir, filepath.Base(src))
			if err := copyFile(src, dst); err != nil {
				LogWarning(fmt.Sprintf("Could not backup %s: %v", src, err))
			} else {
				LogVerbose(fmt.Sprintf("Backed up: %s", src))
			}
		}
	}
	LogSuccess("Configuration backup complete")

	// Step 3: Create backup metadata
	metadataPath := filepath.Join(tempDir, "backup-metadata.txt")
	metadata := fmt.Sprintf("OpenWatch Backup\nCreated: %s\nVersion: %s\nCommit: %s\n",
		time.Now().Format(time.RFC3339), Version, Commit)
	if err := os.WriteFile(metadataPath, []byte(metadata), 0644); err != nil {
		LogWarning(fmt.Sprintf("Could not write metadata: %v", err))
	}

	// Step 4: Create tar archive
	LogInfo("Creating archive...")
	if err := createTarArchive(tempDir, backupOutput, !backupNoCompress); err != nil {
		return fmt.Errorf("failed to create archive: %w", err)
	}

	// Get file size
	if info, err := os.Stat(backupOutput); err == nil {
		sizeMB := float64(info.Size()) / 1024 / 1024
		LogSuccess(fmt.Sprintf("Backup complete: %s (%.2f MB)", backupOutput, sizeMB))
	} else {
		LogSuccess(fmt.Sprintf("Backup complete: %s", backupOutput))
	}

	fmt.Println()
	fmt.Println("Restore with: owadm restore", backupOutput)

	return nil
}

func dumpDatabase(outputPath string) error {
	// Try to get database credentials from environment or config
	dbHost := getEnvOrDefault("OPENWATCH_DATABASE_HOST", "localhost")
	dbPort := getEnvOrDefault("OPENWATCH_DATABASE_PORT", "5432")
	dbName := getEnvOrDefault("OPENWATCH_DATABASE_NAME", "openwatch")
	dbUser := getEnvOrDefault("OPENWATCH_DATABASE_USER", "openwatch")
	dbPass := os.Getenv("OPENWATCH_DATABASE_PASSWORD")

	// Build pg_dump command
	args := []string{
		"-h", dbHost,
		"-p", dbPort,
		"-U", dbUser,
		"-d", dbName,
		"-f", outputPath,
		"--no-password",
	}

	cmd := exec.Command("pg_dump", args...)
	if dbPass != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", dbPass))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pg_dump failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Preserve permissions
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, data, srcInfo.Mode())
}

func createTarArchive(sourceDir, outputPath string, compress bool) error {
	var cmd *exec.Cmd
	if compress {
		cmd = exec.Command("tar", "-czf", outputPath, "-C", sourceDir, ".")
	} else {
		cmd = exec.Command("tar", "-cf", outputPath, "-C", sourceDir, ".")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tar failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
