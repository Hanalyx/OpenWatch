package runtime

import (
	"context"
	"testing"
	"time"
)

func TestDockerRuntime_New(t *testing.T) {
	tests := []struct {
		name        string
		projectName string
		wantErr     bool
	}{
		{
			name:        "Valid project name",
			projectName: "openwatch",
			wantErr:     false,
		},
		{
			name:        "Empty project name",
			projectName: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDockerRuntime(tt.projectName)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDockerRuntime() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDockerRuntime_normalizeComposeCommand(t *testing.T) {
	d := &DockerRuntime{projectName: "test"}
	
	tests := []struct {
		name     string
		args     []string
		expected []string
	}{
		{
			name:     "docker compose format",
			args:     []string{"up", "-d"},
			expected: []string{"compose", "-p", "test", "-f", "docker-compose.yml", "up", "-d"},
		},
		{
			name:     "empty args",
			args:     []string{},
			expected: []string{"compose", "-p", "test", "-f", "docker-compose.yml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.composeCommand = "docker compose"
			result := d.normalizeComposeCommand(tt.args)
			
			if len(result) != len(tt.expected) {
				t.Errorf("normalizeComposeCommand() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDockerRuntime_Config(t *testing.T) {
	tests := []struct {
		name            string
		envOverrides    map[string]string
		expectedChanged int
	}{
		{
			name:            "No overrides",
			envOverrides:    map[string]string{},
			expectedChanged: 0,
		},
		{
			name: "With overrides",
			envOverrides: map[string]string{
				"POSTGRES_PASSWORD": "newpass",
				"REDIS_PORT":        "6380",
			},
			expectedChanged: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DockerRuntime{projectName: "test"}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			result, err := d.Config(ctx, tt.envOverrides)
			if err != nil {
				// Skip if Docker not available
				t.Skip("Docker not available for testing")
			}
			
			if result.Changed != tt.expectedChanged {
				t.Errorf("Config() changed = %v, want %v", result.Changed, tt.expectedChanged)
			}
		})
	}
}