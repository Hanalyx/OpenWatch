package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/hanalyx/openwatch/internal/owadm/runtime"
)

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:   "exec <service> <command>",
	Short: "Execute command in OpenWatch container",
	Long: `Execute a command in a running OpenWatch container.

Examples:
  owadm exec backend bash              # Open bash shell in backend
  owadm exec backend python manage.py # Run Django management command
  owadm exec database psql -U openwatch  # Connect to database`,
	Args: cobra.MinimumNArgs(2),
	RunE: runExec,
}

func init() {
	rootCmd.AddCommand(execCmd)
}

func runExec(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	
	service := args[0]
	command := args[1:]
	
	LogInfo(fmt.Sprintf("Executing in %s: %v", service, command))
	
	// Get or detect runtime
	var rt runtime.Runtime
	var err error
	
	runtimeName := viper.GetString("runtime")
	if runtimeName != "" {
		rt, err = runtime.GetRuntime(runtimeName)
	} else {
		rt, err = runtime.DetectRuntime()
	}
	
	if err != nil {
		LogError(fmt.Sprintf("Runtime error: %v", err))
		return err
	}
	
	// Execute command
	return rt.Exec(ctx, service, command)
}