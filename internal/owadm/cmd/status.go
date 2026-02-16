//go:build container

package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/hanalyx/openwatch/internal/owadm/runtime"
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status of OpenWatch containers",
	Long: `Display the current status of OpenWatch containers.

Shows container state, health status, and port mappings.`,
	RunE: runStatus,
	Aliases: []string{"ps"},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	PrintHeader("OpenWatch Status")

	// Get or detect runtime
	var rt runtime.Runtime
	var err error

	runtimeName := viper.GetString("runtime")
	if runtimeName != "" {
		LogVerbose(fmt.Sprintf("Using specified runtime: %s", runtimeName))
		rt, err = runtime.GetRuntime(runtimeName)
	} else {
		LogVerbose("Auto-detecting container runtime...")
		rt, err = runtime.DetectRuntime()
	}

	if err != nil {
		LogError(fmt.Sprintf("Runtime error: %v", err))
		return err
	}

	LogInfo(fmt.Sprintf("Using %s runtime", rt.Name()))

	// Get container status
	status, err := rt.Status(ctx)
	if err != nil {
		LogError(fmt.Sprintf("Failed to get status: %v", err))
		return err
	}

	// Display overall status
	fmt.Println()
	fmt.Printf("%s %s\n", bold("Overall Status:"), getStatusColor(status.Overall))
	fmt.Println()

	// Check service health by trying to connect
	services := checkServiceHealth()

	// Display service status in a table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, bold("SERVICE\tSTATUS\tHEALTH\tPORTS"))
	fmt.Fprintln(w, strings.Repeat("-", 60))

	for _, svc := range services {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			svc.Name,
			getStatusColor(svc.State),
			getHealthColor(svc.Health),
			strings.Join(svc.Ports, ", "),
		)
	}

	w.Flush()

	// Display access URLs if services are running
	if hasRunningServices(services) {
		fmt.Println()
		PrintHeader("Access URLs")
		fmt.Printf("  %s %s\n", bold("Frontend:"), green("http://localhost:3001"))
		fmt.Printf("  %s %s\n", bold("Backend:"), green("http://localhost:8000"))
		fmt.Printf("  %s %s\n", bold("API Docs:"), green("http://localhost:8000/docs"))
	}

	// Display helpful commands
	fmt.Println()
	PrintHeader("Commands")
	if status.Overall != "Running" {
		fmt.Printf("  %s %s\n", bold("Start services:"), "owadm start")
	} else {
		fmt.Printf("  %s %s\n", bold("View logs:"), "owadm logs <service> --follow")
		fmt.Printf("  %s %s\n", bold("Stop services:"), "owadm stop")
		fmt.Printf("  %s %s\n", bold("Restart services:"), "owadm restart")
	}
	fmt.Println()

	return nil
}

// checkServiceHealth performs basic health checks on services
func checkServiceHealth() []runtime.ServiceStatus {
	// Define OpenWatch services with their expected ports
	services := []runtime.ServiceStatus{
		{
			Name:   "frontend",
			State:  "unknown",
			Health: "unknown",
			Ports:  []string{"3001"},
		},
		{
			Name:   "backend",
			State:  "unknown",
			Health: "unknown",
			Ports:  []string{"8000"},
		},
		{
			Name:   "database",
			State:  "unknown",
			Health: "unknown",
			Ports:  []string{"5432"},
		},
		{
			Name:   "redis",
			State:  "unknown",
			Health: "unknown",
			Ports:  []string{"6379"},
		},
		{
			Name:   "worker",
			State:  "unknown",
			Health: "unknown",
			Ports:  []string{"-"},
		},
	}

	// Simple port-based health check
	// TODO: Implement actual container status checking
	for i := range services {
		if services[i].Name == "frontend" && isPortOpen("localhost", 3001) {
			services[i].State = "running"
			services[i].Health = "healthy"
		} else if services[i].Name == "backend" && isPortOpen("localhost", 8000) {
			services[i].State = "running"
			services[i].Health = "healthy"
		} else if len(services[i].Ports) > 0 && services[i].Ports[0] != "-" {
			services[i].State = "stopped"
			services[i].Health = "-"
		}
	}

	return services
}

// isPortOpen checks if a port is open on the given host
func isPortOpen(host string, port int) bool {
	// Simple TCP connection test
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// getStatusColor returns colored status text
func getStatusColor(status string) string {
	switch strings.ToLower(status) {
	case "running", "up":
		return green(status)
	case "stopped", "down", "exited":
		return red(status)
	case "starting", "restarting":
		return yellow(status)
	default:
		return status
	}
}

// getHealthColor returns colored health status
func getHealthColor(health string) string {
	switch strings.ToLower(health) {
	case "healthy":
		return green(health)
	case "unhealthy":
		return red(health)
	case "starting":
		return yellow(health)
	default:
		return color.New(color.FgHiBlack).Sprint(health)
	}
}

// hasRunningServices checks if any services are running
func hasRunningServices(services []runtime.ServiceStatus) bool {
	for _, svc := range services {
		if strings.ToLower(svc.State) == "running" {
			return true
		}
	}
	return false
}
