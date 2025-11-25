package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/hanalyx/openwatch/internal/owadm/runtime"
)

var (
	force         bool
	removeVolumes bool
)

// stopCmd represents the stop command
var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop OpenWatch containers",
	Long: `Stop OpenWatch containers using the specified or auto-detected runtime.

Examples:
  owadm stop                     # Stop containers
  owadm stop --force             # Force stop containers
  owadm stop --remove-volumes    # Stop and remove volumes`,
	RunE: runStop,
}

func init() {
	rootCmd.AddCommand(stopCmd)

	// Local flags
	stopCmd.Flags().BoolVarP(&force, "force", "f", false, "Force stop containers")
	stopCmd.Flags().BoolVarP(&removeVolumes, "remove-volumes", "v", false, "Remove volumes when stopping")
}

func runStop(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	PrintHeader("Stopping OpenWatch")

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

	// Confirm destructive operations
	if removeVolumes {
		LogWarning("This will remove all data volumes!")
		fmt.Print("Are you sure you want to continue? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			LogInfo("Operation cancelled")
			return nil
		}
	}

	// Stop containers
	LogInfo(fmt.Sprintf("Stopping containers with %s...", rt.Name()))

	// Create a spinner for visual feedback
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Suffix = " Stopping OpenWatch containers..."
	s.Start()

	stopOptions := runtime.StopOptions{
		Force:         force,
		RemoveVolumes: removeVolumes,
		Timeout:       2 * time.Minute,
	}

	err = rt.Stop(ctx, stopOptions)
	s.Stop()

	if err != nil {
		LogError(fmt.Sprintf("Failed to stop containers: %v", err))
		return err
	}

	LogSuccess("OpenWatch containers stopped successfully!")

	if removeVolumes {
		LogWarning("Data volumes have been removed")
	}

	// Print next steps
	fmt.Println()
	PrintHeader("Next Steps")
	fmt.Printf("  %s %s\n", bold("Start again:"), "owadm start")
	if !removeVolumes {
		fmt.Printf("  %s %s\n", bold("Remove data:"), "owadm stop --remove-volumes")
	}
	fmt.Println()

	return nil
}
