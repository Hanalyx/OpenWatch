package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommand(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantError    bool
		checkOutput  func(string) bool
	}{
		{
			name:      "Help flag",
			args:      []string{"--help"},
			wantError: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "OpenWatch Admin utility")
			},
		},
		{
			name:      "Version flag", 
			args:      []string{"--version"},
			wantError: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "owadm version")
			},
		},
		{
			name:      "Invalid flag",
			args:      []string{"--invalid"},
			wantError: true,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "unknown flag")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewRootCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if (err != nil) != tt.wantError {
				t.Errorf("RootCmd.Execute() error = %v, wantError %v", err, tt.wantError)
			}

			output := buf.String()
			if tt.checkOutput != nil && !tt.checkOutput(output) {
				t.Errorf("Unexpected output: %s", output)
			}
		})
	}
}

func TestGetProjectName(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		configValue string
		flagValue   string
		expected    string
	}{
		{
			name:     "Default value",
			expected: "openwatch",
		},
		{
			name:      "Flag takes precedence",
			envValue:  "env-project",
			flagValue: "flag-project",
			expected:  "flag-project",
		},
		{
			name:     "Env value used",
			envValue: "env-project",
			expected: "env-project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore env
			oldEnv := getEnv("OWADM_PROJECT")
			defer setEnv("OWADM_PROJECT", oldEnv)

			if tt.envValue != "" {
				setEnv("OWADM_PROJECT", tt.envValue)
			}

			cmd := &cobra.Command{}
			if tt.flagValue != "" {
				cmd.Flags().String("project", tt.flagValue, "")
			} else {
				cmd.Flags().String("project", "", "")
			}

			result := getProjectName(cmd)
			if result != tt.expected {
				t.Errorf("getProjectName() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Helper functions
func getEnv(key string) string {
	return os.Getenv(key)
}

func setEnv(key, value string) {
	if value == "" {
		os.Unsetenv(key)
	} else {
		os.Setenv(key, value)
	}
}