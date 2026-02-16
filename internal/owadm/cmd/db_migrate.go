// Database migration command - included in all builds (native + container)

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	migrateRevision string
	migrateDowngrade bool
	migrateHistory   bool
)

var dbMigrateCmd = &cobra.Command{
	Use:   "db-migrate",
	Short: "Run database migrations",
	Long: `Run Alembic database migrations for OpenWatch.

This command manages the PostgreSQL database schema using Alembic migrations.
Migrations are located in the backend application directory.

Examples:
  owadm db-migrate                    # Upgrade to latest revision
  owadm db-migrate --revision abc123  # Upgrade to specific revision
  owadm db-migrate --downgrade        # Downgrade one revision
  owadm db-migrate --history          # Show migration history`,
	RunE: runDBMigrate,
}

func init() {
	rootCmd.AddCommand(dbMigrateCmd)

	dbMigrateCmd.Flags().StringVar(&migrateRevision, "revision", "head", "Target revision (default: head)")
	dbMigrateCmd.Flags().BoolVar(&migrateDowngrade, "downgrade", false, "Downgrade instead of upgrade")
	dbMigrateCmd.Flags().BoolVar(&migrateHistory, "history", false, "Show migration history")
}

func runDBMigrate(cmd *cobra.Command, args []string) error {
	PrintHeader("Database Migration")

	// Find the backend directory with Alembic config
	backendDir := findBackendDir()
	if backendDir == "" {
		return fmt.Errorf("could not find OpenWatch backend directory with alembic.ini")
	}

	LogVerbose(fmt.Sprintf("Using backend directory: %s", backendDir))

	// Check if alembic.ini exists
	alembicConfig := filepath.Join(backendDir, "alembic.ini")
	if _, err := os.Stat(alembicConfig); os.IsNotExist(err) {
		return fmt.Errorf("alembic.ini not found in %s", backendDir)
	}

	// Activate virtual environment if it exists
	venvPath := findVenvPath()
	var alembicCmd string
	if venvPath != "" {
		alembicCmd = filepath.Join(venvPath, "bin", "alembic")
		LogVerbose(fmt.Sprintf("Using virtualenv: %s", venvPath))
	} else {
		alembicCmd = "alembic"
	}

	// Show history if requested
	if migrateHistory {
		return showMigrationHistory(alembicCmd, backendDir)
	}

	// Run migration
	if migrateDowngrade {
		return runDowngrade(alembicCmd, backendDir, migrateRevision)
	}

	return runUpgrade(alembicCmd, backendDir, migrateRevision)
}

func findBackendDir() string {
	// Check common locations
	locations := []string{
		"/opt/openwatch/backend",
		"/usr/share/openwatch/backend",
		"./backend",
		"../backend",
	}

	for _, loc := range locations {
		alembicPath := filepath.Join(loc, "alembic.ini")
		if _, err := os.Stat(alembicPath); err == nil {
			absPath, _ := filepath.Abs(loc)
			return absPath
		}
	}

	return ""
}

func findVenvPath() string {
	// Check common virtualenv locations
	locations := []string{
		"/opt/openwatch/venv",
		"/usr/share/openwatch/venv",
		"./venv",
		"../.venv",
	}

	for _, loc := range locations {
		activatePath := filepath.Join(loc, "bin", "activate")
		if _, err := os.Stat(activatePath); err == nil {
			absPath, _ := filepath.Abs(loc)
			return absPath
		}
	}

	return ""
}

func showMigrationHistory(alembicCmd, backendDir string) error {
	LogInfo("Migration history:")
	fmt.Println()

	execCmd := exec.Command(alembicCmd, "history", "--verbose")
	execCmd.Dir = backendDir
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Env = os.Environ()

	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("failed to show history: %w", err)
	}

	fmt.Println()
	LogInfo("Current revision:")
	currentCmd := exec.Command(alembicCmd, "current")
	currentCmd.Dir = backendDir
	currentCmd.Stdout = os.Stdout
	currentCmd.Stderr = os.Stderr
	currentCmd.Env = os.Environ()

	return currentCmd.Run()
}

func runUpgrade(alembicCmd, backendDir, revision string) error {
	LogInfo(fmt.Sprintf("Upgrading database to revision: %s", revision))

	execCmd := exec.Command(alembicCmd, "upgrade", revision)
	execCmd.Dir = backendDir
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Env = os.Environ()

	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	LogSuccess("Database migration complete")

	// Show current revision
	fmt.Println()
	LogInfo("Current revision:")
	currentCmd := exec.Command(alembicCmd, "current")
	currentCmd.Dir = backendDir
	currentCmd.Stdout = os.Stdout
	currentCmd.Stderr = os.Stderr
	currentCmd.Env = os.Environ()

	return currentCmd.Run()
}

func runDowngrade(alembicCmd, backendDir, revision string) error {
	// For downgrade, default to -1 (one revision back) instead of head
	if revision == "head" {
		revision = "-1"
	}

	LogWarning(fmt.Sprintf("Downgrading database to revision: %s", revision))

	execCmd := exec.Command(alembicCmd, "downgrade", revision)
	execCmd.Dir = backendDir
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Env = os.Environ()

	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("downgrade failed: %w", err)
	}

	LogSuccess("Database downgrade complete")

	// Show current revision
	fmt.Println()
	LogInfo("Current revision:")
	currentCmd := exec.Command(alembicCmd, "current")
	currentCmd.Dir = backendDir
	currentCmd.Stdout = os.Stdout
	currentCmd.Stderr = os.Stderr
	currentCmd.Env = os.Environ()

	return currentCmd.Run()
}
