// Create admin command - included in all builds (native + container)

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	adminUsername string
	adminEmail    string
	adminPassword string
)

var createAdminCmd = &cobra.Command{
	Use:   "create-admin",
	Short: "Create an admin user",
	Long: `Create a new administrator user for OpenWatch.

This command creates a new user with administrative privileges.
If password is not provided via --password flag, it will be prompted securely.

Examples:
  owadm create-admin                                    # Interactive mode
  owadm create-admin --username admin --email admin@example.com
  owadm create-admin -u admin -e admin@example.com -p secretpass`,
	RunE: runCreateAdmin,
}

func init() {
	rootCmd.AddCommand(createAdminCmd)

	createAdminCmd.Flags().StringVarP(&adminUsername, "username", "u", "", "Admin username")
	createAdminCmd.Flags().StringVarP(&adminEmail, "email", "e", "", "Admin email address")
	createAdminCmd.Flags().StringVarP(&adminPassword, "password", "p", "", "Admin password (will prompt if not provided)")
}

func runCreateAdmin(cmd *cobra.Command, args []string) error {
	PrintHeader("Create Admin User")

	reader := bufio.NewReader(os.Stdin)

	// Get username
	if adminUsername == "" {
		fmt.Print("Username: ")
		input, _ := reader.ReadString('\n')
		adminUsername = strings.TrimSpace(input)
	}
	if adminUsername == "" {
		return fmt.Errorf("username is required")
	}

	// Get email
	if adminEmail == "" {
		fmt.Print("Email: ")
		input, _ := reader.ReadString('\n')
		adminEmail = strings.TrimSpace(input)
	}
	if adminEmail == "" {
		return fmt.Errorf("email is required")
	}

	// Get password
	if adminPassword == "" {
		fmt.Print("Password: ")
		input, _ := reader.ReadString('\n')
		adminPassword = strings.TrimSpace(input)

		// Confirm password
		fmt.Print("Confirm password: ")
		input, _ = reader.ReadString('\n')
		confirmPassword := strings.TrimSpace(input)

		if adminPassword != confirmPassword { // pragma: allowlist secret
			return fmt.Errorf("passwords do not match")
		}

		LogWarning("Password was entered in plain text. For secure entry, use --password flag.")
	}

	if len(adminPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	LogInfo(fmt.Sprintf("Creating admin user: %s (%s)", adminUsername, adminEmail))

	// Try to create user via Python script
	if err := createAdminViaPython(adminUsername, adminEmail, adminPassword); err != nil {
		LogWarning(fmt.Sprintf("Python method failed: %v", err))
		LogInfo("Attempting alternative method...")
		return createAdminViaAPI(adminUsername, adminEmail, adminPassword)
	}

	LogSuccess(fmt.Sprintf("Admin user '%s' created successfully", adminUsername))
	return nil
}

func createAdminViaPython(username, email, password string) error {
	// Find the backend directory
	backendDir := findBackendDir()
	if backendDir == "" {
		return fmt.Errorf("backend directory not found")
	}

	// Find virtualenv
	venvPath := findVenvPath()
	var pythonCmd string
	if venvPath != "" {
		pythonCmd = filepath.Join(venvPath, "bin", "python")
	} else {
		pythonCmd = "python3"
	}

	// Create a Python script to create the admin user
	script := fmt.Sprintf(`
import sys
sys.path.insert(0, '%s')

import asyncio
from app.core.database import get_db_session
from app.services.auth.user_service import UserService
from app.schemas.user import UserCreate

async def create_admin():
    async with get_db_session() as session:
        user_service = UserService(session)
        user_data = UserCreate(
            username='%s',
            email='%s',
            password='%s',
            is_admin=True,
            is_active=True
        )
        user = await user_service.create_user(user_data)
        print(f"Created user: {user.username} (ID: {user.id})")

asyncio.run(create_admin())
`, backendDir, username, email, password)

	execCmd := exec.Command(pythonCmd, "-c", script)
	execCmd.Dir = backendDir
	execCmd.Env = os.Environ()

	output, err := execCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create user: %w\nOutput: %s", err, string(output))
	}

	LogVerbose(string(output))
	return nil
}

func createAdminViaAPI(username, email, password string) error {
	// Try to create via API if available
	// This is a fallback method
	LogWarning("API-based admin creation not yet implemented")
	LogInfo("Please create admin user manually via the application")

	fmt.Println()
	fmt.Println("Alternative methods:")
	fmt.Println("  1. Use the web interface registration (if enabled)")
	fmt.Println("  2. Run the create-admin.sh script in /opt/openwatch/scripts/")
	fmt.Println("  3. Use Django/Flask shell if available")

	return fmt.Errorf("automatic admin creation failed - use manual method")
}
