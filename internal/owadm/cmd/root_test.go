package cmd

import (
	"bytes"
	"strings"
	"testing"
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
				return strings.Contains(output, "OpenWatch Admin")
			},
		},
		{
			name:      "Version flag", 
			args:      []string{"--version"},
			wantError: false,
			checkOutput: func(output string) bool {
				return strings.Contains(output, "OpenWatch Admin")
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
			cmd := rootCmd
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

func TestVersionCommand(t *testing.T) {
	// Test version information is available
	if Version == "" {
		Version = "dev"
	}
	if Commit == "" {
		Commit = "unknown"
	}
	if BuildTime == "" {
		BuildTime = "unknown"
	}
	
	t.Logf("Version: %s, Commit: %s, BuildTime: %s", Version, Commit, BuildTime)
}

