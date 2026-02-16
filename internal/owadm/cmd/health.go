// Health check command - included in all builds (native + container)

package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
)

var (
	healthJSON    bool
	healthVerbose bool
)

// HealthStatus represents the health of a component
type HealthStatus struct {
	Component string `json:"component"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	Latency   string `json:"latency,omitempty"`
}

// OverallHealth represents the overall system health
type OverallHealth struct {
	Status     string         `json:"status"`
	Timestamp  string         `json:"timestamp"`
	Components []HealthStatus `json:"components"`
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check health of OpenWatch components",
	Long: `Perform health checks on all OpenWatch components.

Checks the following:
  - PostgreSQL database connectivity
  - Redis connectivity
  - API endpoint health
  - Celery workers (if applicable)
  - Configuration file validity

Examples:
  owadm health              # Basic health check
  owadm health --json       # Output as JSON
  owadm health --verbose    # Show detailed information`,
	RunE: runHealth,
}

func init() {
	rootCmd.AddCommand(healthCmd)

	healthCmd.Flags().BoolVar(&healthJSON, "json", false, "Output as JSON")
	healthCmd.Flags().BoolVar(&healthVerbose, "verbose", false, "Show detailed information")
}

func runHealth(cmd *cobra.Command, args []string) error {
	if !healthJSON {
		PrintHeader("OpenWatch Health Check")
	}

	health := OverallHealth{
		Timestamp:  time.Now().Format(time.RFC3339),
		Components: []HealthStatus{},
	}

	allHealthy := true

	// Check PostgreSQL
	dbStatus := checkPostgreSQL()
	health.Components = append(health.Components, dbStatus)
	if dbStatus.Status != "healthy" {
		allHealthy = false
	}

	// Check Redis
	redisStatus := checkRedis()
	health.Components = append(health.Components, redisStatus)
	if redisStatus.Status != "healthy" {
		allHealthy = false
	}

	// Check API endpoint
	apiStatus := checkAPI()
	health.Components = append(health.Components, apiStatus)
	if apiStatus.Status != "healthy" {
		allHealthy = false
	}

	// Check configuration
	configStatus := checkConfig()
	health.Components = append(health.Components, configStatus)
	if configStatus.Status != "healthy" {
		allHealthy = false
	}

	// Check systemd services (native) or containers
	serviceStatus := checkServices()
	health.Components = append(health.Components, serviceStatus)
	if serviceStatus.Status != "healthy" {
		allHealthy = false
	}

	// Set overall status
	if allHealthy {
		health.Status = "healthy"
	} else {
		health.Status = "unhealthy"
	}

	// Output results
	if healthJSON {
		return outputJSON(health)
	}

	return outputTable(health)
}

func checkPostgreSQL() HealthStatus {
	status := HealthStatus{
		Component: "PostgreSQL",
		Status:    "healthy",
	}

	start := time.Now()

	host := getEnvOrDefault("OPENWATCH_DATABASE_HOST", "localhost")
	port := getEnvOrDefault("OPENWATCH_DATABASE_PORT", "5432")

	// Check TCP connectivity
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), 3*time.Second)
	if err != nil {
		status.Status = "unhealthy"
		status.Message = fmt.Sprintf("Cannot connect to %s:%s", host, port)
	} else {
		conn.Close()
		// Try pg_isready for more detailed check
		cmd := exec.Command("pg_isready", "-h", host, "-p", port, "-q")
		if err := cmd.Run(); err != nil {
			status.Status = "degraded"
			status.Message = fmt.Sprintf("Port %s:%s reachable but pg_isready failed", host, port)
		} else {
			status.Message = fmt.Sprintf("PostgreSQL ready at %s:%s", host, port)
		}
	}

	status.Latency = time.Since(start).String()
	return status
}

func checkRedis() HealthStatus {
	status := HealthStatus{
		Component: "Redis",
		Status:    "healthy",
	}

	start := time.Now()

	host := getEnvOrDefault("OPENWATCH_REDIS_HOST", "localhost")
	port := getEnvOrDefault("OPENWATCH_REDIS_PORT", "6379")

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), 3*time.Second)
	if err != nil {
		status.Status = "unhealthy"
		status.Message = fmt.Sprintf("Cannot connect to %s:%s", host, port)
	} else {
		conn.Close()
		status.Message = fmt.Sprintf("Connected to %s:%s", host, port)
	}

	status.Latency = time.Since(start).String()
	return status
}

func checkAPI() HealthStatus {
	status := HealthStatus{
		Component: "API",
		Status:    "healthy",
	}

	start := time.Now()

	apiHost := getEnvOrDefault("OPENWATCH_API_HOST", "localhost")
	apiPort := getEnvOrDefault("OPENWATCH_API_PORT", "8000")
	healthURL := fmt.Sprintf("http://%s:%s/health", apiHost, apiPort)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		status.Status = "unhealthy"
		status.Message = fmt.Sprintf("Cannot reach API: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			status.Message = fmt.Sprintf("API responding at %s:%s", apiHost, apiPort)
		} else {
			status.Status = "degraded"
			status.Message = fmt.Sprintf("API returned status %d", resp.StatusCode)
		}
	}

	status.Latency = time.Since(start).String()
	return status
}

func checkConfig() HealthStatus {
	status := HealthStatus{
		Component: "Configuration",
		Status:    "healthy",
	}

	configPaths := []string{
		"/etc/openwatch/ow.yml",
		"/etc/openwatch/secrets.env",
	}

	missing := []string{}
	for _, path := range configPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			missing = append(missing, path)
		}
	}

	if len(missing) > 0 {
		status.Status = "unhealthy"
		status.Message = fmt.Sprintf("Missing: %v", missing)
	} else {
		status.Message = "All configuration files present"
	}

	return status
}

func checkServices() HealthStatus {
	status := HealthStatus{
		Component: "Services",
		Status:    "healthy",
	}

	// Try systemctl first (native installation)
	services := []string{
		"openwatch-api",
		"openwatch-worker@1",
		"openwatch-beat",
	}

	running := 0
	total := len(services)

	for _, svc := range services {
		cmd := exec.Command("systemctl", "is-active", "--quiet", svc)
		if err := cmd.Run(); err == nil {
			running++
		}
	}

	if running == total {
		status.Message = fmt.Sprintf("All %d services running", total)
	} else if running > 0 {
		status.Status = "degraded"
		status.Message = fmt.Sprintf("%d/%d services running", running, total)
	} else {
		// Check if services exist at all
		cmd := exec.Command("systemctl", "list-units", "--type=service", "--all")
		output, _ := cmd.Output()
		if len(output) > 0 && !contains(string(output), "openwatch") {
			status.Status = "unknown"
			status.Message = "No OpenWatch services found (container mode?)"
		} else {
			status.Status = "unhealthy"
			status.Message = "No services running"
		}
	}

	return status
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func outputJSON(health OverallHealth) error {
	data, err := json.MarshalIndent(health, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func outputTable(health OverallHealth) error {
	// Print component status
	for _, comp := range health.Components {
		var statusIcon string
		switch comp.Status {
		case "healthy":
			statusIcon = green("[OK]")
		case "degraded":
			statusIcon = yellow("[WARN]")
		case "unhealthy":
			statusIcon = red("[FAIL]")
		default:
			statusIcon = blue("[?]")
		}

		fmt.Printf("%s %-15s %s", statusIcon, comp.Component, comp.Message)
		if comp.Latency != "" && healthVerbose {
			fmt.Printf(" (%s)", comp.Latency)
		}
		fmt.Println()
	}

	// Print overall status
	fmt.Println()
	if health.Status == "healthy" {
		LogSuccess("All components healthy")
	} else {
		LogError("Some components are unhealthy")
	}

	return nil
}
