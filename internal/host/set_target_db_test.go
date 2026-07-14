// @spec system-compliance-lens
//
// Host compliance-target (Phase 3 compliance-targets): host.SetTarget's
// set/clear/validate/not-found and GetByID surfacing the stored value. The
// per-host target is the override that wins in host_effective_target; unlike a
// group target it carries no site-only constraint. Kept in its own file so its
// spec annotation does not re-attribute the system-host-inventory tests in
// host_test.go.

package host

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// @ac AC-08
// AC-08: host.SetTarget sets/clears/validates the host's own target_framework,
// returns ErrHostNotFound for an unknown host, and GetByID surfaces the value.
func TestSetTarget_HostOverride(t *testing.T) {
	t.Run("system-compliance-lens/AC-08", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		ctx := context.Background()

		h, err := svc.CreateHost(ctx, CreateParams{
			Hostname: "target.example.com", IPAddress: "192.0.2.20",
			Environment: "production", CreatedBy: createdBy,
		})
		if err != nil {
			t.Fatalf("CreateHost: %v", err)
		}
		// A fresh host has no own target.
		if h.TargetFramework != nil {
			t.Errorf("new host TargetFramework = %v, want nil", h.TargetFramework)
		}

		// Set a valid family.
		got, err := svc.SetTarget(ctx, h.ID, "stig")
		if err != nil {
			t.Fatalf("SetTarget(stig): %v", err)
		}
		if got.TargetFramework == nil || *got.TargetFramework != "stig" {
			t.Errorf("target = %v, want stig", got.TargetFramework)
		}
		// GetByID surfaces the stored value.
		reread, err := svc.GetByID(ctx, h.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if reread.TargetFramework == nil || *reread.TargetFramework != "stig" {
			t.Errorf("GetByID target = %v, want stig", reread.TargetFramework)
		}

		// Clear it (empty family) -> nil.
		cleared, err := svc.SetTarget(ctx, h.ID, "")
		if err != nil {
			t.Fatalf("SetTarget(clear): %v", err)
		}
		if cleared.TargetFramework != nil {
			t.Errorf("cleared target = %v, want nil", cleared.TargetFramework)
		}

		// Invalid family value rejected.
		if _, err := svc.SetTarget(ctx, h.ID, "BAD SPACE"); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("SetTarget(bad) err = %v, want ErrInvalidTarget", err)
		}

		// Unknown host -> ErrHostNotFound.
		if _, err := svc.SetTarget(ctx, uuid.New(), "stig"); !errors.Is(err, ErrHostNotFound) {
			t.Errorf("SetTarget(unknown) err = %v, want ErrHostNotFound", err)
		}
	})
}
