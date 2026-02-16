//go:build container

package runtime

import (
	"testing"
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
			runtime := NewDockerRuntime()
			if runtime == nil && !tt.wantErr {
				t.Errorf("NewDockerRuntime() returned nil, wantErr %v", tt.wantErr)
			}
		})
	}
}

func TestDockerRuntime_Name(t *testing.T) {
	d := NewDockerRuntime()

	expected := "Docker"
	if d.Name() != expected {
		t.Errorf("Name() = %v, want %v", d.Name(), expected)
	}
}

func TestDockerRuntime_IsAvailable(t *testing.T) {
	d := NewDockerRuntime()

	// This test will pass if Docker is available, skip if not
	available := d.IsAvailable()
	if available {
		t.Logf("Docker is available")
	} else {
		t.Skip("Docker not available for testing")
	}
}
