//go:build container

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/hanalyx/openwatch/internal/owadm/runtime"
	"github.com/hanalyx/openwatch/internal/owadm/utils"
)

var (
	detach        bool
	build         bool
	forceRecreate bool
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start OpenWatch containers",
	Long: `Start OpenWatch containers using the specified or auto-detected runtime.

Examples:
  owadm start                    # Start with auto-detected runtime
  owadm start --runtime podman   # Start with Podman
  owadm start --env dev          # Start development environment
  owadm start --build            # Rebuild images before starting`,
	RunE: runStart,
}

func init() {
	rootCmd.AddCommand(startCmd)

	// Local flags
	startCmd.Flags().BoolVarP(&detach, "detach", "d", true, "Run containers in background")
	startCmd.Flags().BoolVar(&build, "build", false, "Build images before starting")
	startCmd.Flags().BoolVar(&forceRecreate, "force-recreate", false, "Recreate containers even if config hasn't changed")
}

func runStart(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	PrintHeader("Starting OpenWatch")

	// Check prerequisites
	LogInfo("Checking prerequisites...")
	if err := utils.CheckPrerequisites(); err != nil {
		LogError(fmt.Sprintf("Prerequisites check failed: %v", err))
		return err
	}
	LogSuccess("Prerequisites check passed")

	// Get or detect runtime
	var rt runtime.Runtime
	var err error

	runtimeName := viper.GetString("runtime")
	if runtimeName != "" {
		LogInfo(fmt.Sprintf("Using specified runtime: %s", runtimeName))
		rt, err = runtime.GetRuntime(runtimeName)
	} else {
		LogInfo("Auto-detecting container runtime...")
		rt, err = runtime.DetectRuntime()
		if err == nil {
			LogSuccess(fmt.Sprintf("Detected runtime: %s", rt.Name()))
		}
	}

	if err != nil {
		LogError(fmt.Sprintf("Runtime error: %v", err))
		return err
	}

	// Check environment files
	env := viper.GetString("environment")
	LogInfo(fmt.Sprintf("Environment: %s", env))

	if err := utils.CheckEnvironmentFiles(); err != nil {
		// Handle different types of environment issues
		if err.Error() == "production installation detected (source files not present)" {
			LogInfo("Production installation detected - using compose files from system directory")
		} else if err.Error() == ".env file not found" {
			LogWarning("Environment file missing - creating default .env file")
			if err := utils.CreateDefaultEnvFile(); err != nil {
				LogError(fmt.Sprintf("Failed to create .env file: %v", err))
				return err
			}
			LogSuccess("Created default .env file")
		} else {
			LogWarning(fmt.Sprintf("Environment check: %v", err))
			// Create default .env if it doesn't exist
			if err := utils.CreateDefaultEnvFile(); err != nil {
				LogError(fmt.Sprintf("Failed to create .env file: %v", err))
				return err
			}
			LogSuccess("Created default .env file")
		}
	}

	// Create required directories
	LogInfo("Creating required directories...")
	if err := utils.CreateRequiredDirectories(); err != nil {
		LogError(fmt.Sprintf("Failed to create directories: %v", err))
		return err
	}

	// Generate security keys if needed
	if err := utils.EnsureSecurityKeys(); err != nil {
		LogError(fmt.Sprintf("Failed to setup security keys: %v", err))
		return err
	}
	LogSuccess("Security keys are ready")

	// Start containers
	LogInfo(fmt.Sprintf("Starting containers with %s...", rt.Name()))

	// Create a spinner for visual feedback
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Suffix = " Starting OpenWatch containers..."
	s.Start()

	startOptions := runtime.StartOptions{
		Detach:        detach,
		Build:         build,
		ForceRecreate: forceRecreate,
		Environment:   env,
		Timeout:       5 * time.Minute,
	}

	err = rt.Start(ctx, startOptions)
	s.Stop()

	if err != nil {
		LogError(fmt.Sprintf("Failed to start containers: %v", err))
		return err
	}

	LogSuccess("OpenWatch containers started successfully!")

	// Wait a moment for services to initialize
	if detach {
		LogInfo("Waiting for services to initialize...")
		time.Sleep(3 * time.Second)
	}

	// Print access information
	fmt.Println()
	PrintHeader("Access URLs")
	fmt.Printf("  %s %s\n", bold("Frontend:"), green("http://localhost:3001"))
	fmt.Printf("  %s %s\n", bold("Backend:"), green("http://localhost:8000"))
	fmt.Printf("  %s %s\n", bold("API Docs:"), green("http://localhost:8000/docs"))
	fmt.Println()

	// Print helpful commands
	PrintHeader("Useful Commands")
	fmt.Printf("  %s %s\n", bold("View logs:"), "owadm logs <service> --follow")
	fmt.Printf("  %s %s\n", bold("Check status:"), "owadm status")
	fmt.Printf("  %s %s\n", bold("Stop services:"), "owadm stop")
	fmt.Println()

	// Check if we should create admin user
	if env == "dev" || os.Getenv("OWADM_CREATE_ADMIN") == "true" {
		LogInfo("Development environment detected")
		fmt.Printf("\n%s You may want to create an admin user:\n", yellow("TIP:"))
		fmt.Printf("    owadm exec backend python app/init_admin.py\n\n")
	}

	return nil
}
