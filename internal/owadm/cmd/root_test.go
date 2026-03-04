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
				// rootCmd.Version is set at init time; verify it contains the codename
				return strings.Contains(rootCmd.Version, Codename)
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

func TestVersionInfo(t *testing.T) {
	tests := []struct {
		name  string
		value string
		field string
	}{
		{"Version is set", Version, "Version"},
		{"Codename is set", Codename, "Codename"},
		{"Commit is set", Commit, "Commit"},
		{"BuildTime is set", BuildTime, "BuildTime"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("%s must not be empty", tt.field)
			}
		})
	}
	if Codename == "" {
		t.Error("Codename must not be empty - check ldflags in build scripts")
	}
}
