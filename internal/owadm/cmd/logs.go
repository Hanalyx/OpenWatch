//go:build container

package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/hanalyx/openwatch/internal/owadm/runtime"
)

var (
	follow     bool
	tail       string
	since      string
	timestamps bool
)

// logsCmd represents the logs command
var logsCmd = &cobra.Command{
	Use:   "logs [service]",
	Short: "View logs from OpenWatch containers",
	Long: `View logs from OpenWatch containers.

Examples:
  owadm logs                    # Show logs from all services
  owadm logs backend            # Show backend logs
  owadm logs frontend --follow  # Follow frontend logs
  owadm logs database --tail 100`,
	Args: cobra.MaximumNArgs(1),
	RunE: runLogs,
}

func init() {
	rootCmd.AddCommand(logsCmd)

	// Local flags
	logsCmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	logsCmd.Flags().StringVar(&tail, "tail", "100", "Number of lines to show from end of logs")
	logsCmd.Flags().StringVar(&since, "since", "", "Show logs since timestamp")
	logsCmd.Flags().BoolVarP(&timestamps, "timestamps", "t", false, "Show timestamps")
}

func runLogs(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Default to backend if no service specified
	service := "backend"
	if len(args) > 0 {
		service = args[0]
	}

	LogInfo(fmt.Sprintf("Viewing logs for service: %s", service))

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

	// Show logs
	logOptions := runtime.LogOptions{
		Follow:     follow,
		Tail:       tail,
		Since:      since,
		Timestamps: timestamps,
	}

	fmt.Println() // Empty line before logs
	return rt.Logs(ctx, service, logOptions)
}
