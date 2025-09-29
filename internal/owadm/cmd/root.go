package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Build information (set by ldflags)
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"

	// Global flags
	cfgFile         string
	runtimeFlag     string
	environment     string
	verbose         bool
	noColor         bool
	configPath      string

	// Color functions
	blue    = color.New(color.FgBlue).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	bold    = color.New(color.Bold).SprintFunc()
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "owadm",
	Short: "OpenWatch Admin - Container management utility",
	Long: bold("OpenWatch Admin (owadm)") + ` - A fast, intuitive CLI for managing OpenWatch containers.

Simplifies container operations for OpenWatch SCAP compliance scanning platform.
Supports both Docker and Podman runtimes with automatic detection.`,
	Version: fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildTime),
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	
	// Add subcommands
	rootCmd.AddCommand(validateConfigCmd)

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&runtimeFlag, "runtime", "r", "", "Container runtime: docker or podman (auto-detected if not specified)")
	rootCmd.PersistentFlags().StringVarP(&environment, "env", "e", "prod", "Environment: dev or prod")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file (default: .owadm.yaml)")

	// Bind flags to viper
	viper.BindPFlag("runtime", rootCmd.PersistentFlags().Lookup("runtime"))
	viper.BindPFlag("environment", rootCmd.PersistentFlags().Lookup("environment"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("no-color", rootCmd.PersistentFlags().Lookup("no-color"))

	// Disable color if requested
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if noColor {
			color.NoColor = true
		}
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in current directory
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".owadm")
	}

	// Read in environment variables that match
	viper.SetEnvPrefix("OWADM")
	viper.AutomaticEnv()

	// If a config file is found, read it in
	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

// Helper functions for consistent output
func LogInfo(msg string) {
	fmt.Printf("%s %s\n", blue("[INFO]"), msg)
}

func LogSuccess(msg string) {
	fmt.Printf("%s %s\n", green("[SUCCESS]"), msg)
}

func LogWarning(msg string) {
	fmt.Printf("%s %s\n", yellow("[WARNING]"), msg)
}

func LogError(msg string) {
	fmt.Printf("%s %s\n", red("[ERROR]"), msg)
}

func LogVerbose(msg string) {
	if verbose {
		fmt.Printf("%s %s\n", color.New(color.FgCyan).Sprint("[VERBOSE]"), msg)
	}
}

// PrintHeader prints a styled header
func PrintHeader(title string) {
	fmt.Println()
	fmt.Println(bold(title))
	fmt.Println(bold("=" + stringRepeat("=", len(title))))
	fmt.Println()
}

// stringRepeat repeats a string n times
func stringRepeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}