package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/hanalyx/openwatch/internal/owadm/runtime"
)

var (
	// Scan command flags
	profile    string
	target     string
	content    string
	outputDir  string
	parallel   int
	ruleID     string
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Execute SCAP compliance scans",
	Long: `Execute SCAP compliance scans on local or remote hosts.

Examples:
  owadm scan --profile stig-rhel8 --target localhost
  owadm scan --profile cis-ubuntu --target 192.168.1.100
  owadm scan --profile custom --content /path/to/scap.xml --target host1,host2,host3
  owadm scan --profile stig-rhel8 --rule xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs --target localhost`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Scan flags
	scanCmd.Flags().StringVarP(&profile, "profile", "p", "", "SCAP profile ID to scan (required)")
	scanCmd.Flags().StringVarP(&target, "target", "t", "localhost", "Target host(s) - comma separated for multiple")
	scanCmd.Flags().StringVarP(&content, "content", "c", "", "Path to SCAP content file (uses default if not specified)")
	scanCmd.Flags().StringVarP(&outputDir, "output", "o", "/app/data/results", "Output directory for scan results")
	scanCmd.Flags().IntVar(&parallel, "parallel", 5, "Maximum parallel scans for multiple targets")
	scanCmd.Flags().StringVarP(&ruleID, "rule", "r", "", "Scan specific rule only (optional)")

	// Required flags
	scanCmd.MarkFlagRequired("profile")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	LogInfo("Starting SCAP compliance scan...")
	PrintHeader("OpenWatch SCAP Scanner")

	// Validate inputs
	if profile == "" {
		LogError("Profile ID is required")
		return fmt.Errorf("profile ID cannot be empty")
	}

	// Parse targets
	targets := parseTargets(target)
	LogInfo(fmt.Sprintf("Scan targets: %v", targets))
	LogInfo(fmt.Sprintf("Profile: %s", profile))
	if ruleID != "" {
		LogInfo(fmt.Sprintf("Rule-specific scan: %s", ruleID))
	}

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

	// Execute scans
	if len(targets) == 1 && (targets[0] == "localhost" || targets[0] == "127.0.0.1") {
		// Single local scan
		return executeLocalScan(ctx, rt)
	} else if len(targets) == 1 {
		// Single remote scan
		return executeRemoteScan(ctx, rt, targets[0])
	} else {
		// Multiple target scan
		return executeParallelScans(ctx, rt, targets)
	}
}

func parseTargets(targetString string) []string {
	if targetString == "" {
		return []string{"localhost"}
	}

	targets := strings.Split(targetString, ",")
	var cleanTargets []string

	for _, t := range targets {
		clean := strings.TrimSpace(t)
		if clean != "" {
			cleanTargets = append(cleanTargets, clean)
		}
	}

	return cleanTargets
}

func executeLocalScan(ctx context.Context, rt runtime.Runtime) error {
	LogInfo("Executing local SCAP scan...")

	// Build CLI command arguments
	args := []string{
		"python", "/app/backend/app/cli_interface.py", "scan-local",
		"--profile", profile,
	}

	// Add optional arguments
	if content != "" {
		args = append(args, "--content", content)
	}
	if ruleID != "" {
		args = append(args, "--rule", ruleID)
	}
	if outputDir != "" {
		args = append(args, "--output", outputDir+"/local_scan_results.json")
	}

	LogVerbose(fmt.Sprintf("Executing: %v", args))

	// Execute in backend container
	err := rt.Exec(ctx, "backend", args)
	if err != nil {
		LogError(fmt.Sprintf("Local scan failed: %v", err))
		return err
	}

	LogSuccess("Local scan completed successfully!")
	LogInfo(fmt.Sprintf("Results available in: %s", outputDir))

	return nil
}

func executeRemoteScan(ctx context.Context, rt runtime.Runtime, target string) error {
	LogInfo(fmt.Sprintf("Executing remote SCAP scan on: %s", target))

	// Build CLI command arguments
	args := []string{
		"python", "/app/backend/app/cli_interface.py", "scan-remote",
		"--targets", target,
		"--profile", profile,
		"--parallel", "1", // Single target, no parallelism needed
	}

	// Add optional arguments
	if content != "" {
		args = append(args, "--content", content)
	}
	if ruleID != "" {
		args = append(args, "--rule", ruleID)
	}
	if outputDir != "" {
		args = append(args, "--output", outputDir+"/remote_scan_results.json")
	}

	LogVerbose(fmt.Sprintf("Executing: %v", args))

	// Execute in backend container
	err := rt.Exec(ctx, "backend", args)
	if err != nil {
		LogError(fmt.Sprintf("Remote scan failed: %v", err))
		return err
	}

	LogSuccess(fmt.Sprintf("Remote scan on %s completed successfully!", target))
	LogInfo(fmt.Sprintf("Results available in: %s", outputDir))

	return nil
}

func executeParallelScans(ctx context.Context, rt runtime.Runtime, targets []string) error {
	LogInfo(fmt.Sprintf("Executing parallel scans on %d targets (max parallel: %d)", len(targets), parallel))

	// Build CLI command arguments
	targetsStr := strings.Join(targets, ",")
	args := []string{
		"python", "/app/backend/app/cli_interface.py", "scan-remote",
		"--targets", targetsStr,
		"--profile", profile,
		"--parallel", strconv.Itoa(parallel),
	}

	// Add optional arguments
	if content != "" {
		args = append(args, "--content", content)
	}
	if ruleID != "" {
		args = append(args, "--rule", ruleID)
	}
	if outputDir != "" {
		args = append(args, "--output", outputDir+"/batch_scan_results.json")
	}

	LogVerbose(fmt.Sprintf("Executing batch scan: %v", args))

	// Execute in backend container
	err := rt.Exec(ctx, "backend", args)
	if err != nil {
		LogError(fmt.Sprintf("Batch scan failed: %v", err))
		return err
	}

	LogSuccess(fmt.Sprintf("Batch scan completed on %d targets!", len(targets)))
	LogInfo(fmt.Sprintf("Results available in: %s", outputDir))

	return nil
}

// Note: buildScanScript and buildBatchScanScript functions removed
// Now using direct CLI interface via /app/backend/app/cli_interface.py