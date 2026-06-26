package eereg

import (
	"errors"
	"testing"
)

// fakeCapability is a test double whose availability is configurable.
type fakeCapability struct{ avail bool }

func (f fakeCapability) Available() bool { return f.avail }

// restoreDefaults resets the package-level registry after a test mutates it,
// so injection tests don't leak state into one another.
func restoreDefaults() {
	temporal = unavailable{}
	bulk = unavailable{}
	exporter = unavailable{}
	approver = unavailable{}
}

func TestDefaultsAreUnavailable(t *testing.T) {
	restoreDefaults()
	cases := map[string]Capability{
		"temporal": TemporalQueries(),
		"bulk":     BulkRemediation(),
		"export":   SignedExport(),
		"approval": StagedApproval(),
	}
	for name, c := range cases {
		if c.Available() {
			t.Errorf("%s: free-tier default reported Available()=true; want false", name)
		}
	}
}

func TestSetInjectsImplementation(t *testing.T) {
	t.Cleanup(restoreDefaults)

	SetTemporalAnalytics(fakeCapability{avail: true})
	SetBulkRemediator(fakeCapability{avail: true})
	SetSignedExporter(fakeCapability{avail: true})
	SetStagedApprover(fakeCapability{avail: true})

	checks := map[string]Capability{
		"temporal": TemporalQueries(),
		"bulk":     BulkRemediation(),
		"export":   SignedExport(),
		"approval": StagedApproval(),
	}
	for name, c := range checks {
		if !c.Available() {
			t.Errorf("%s: after injection Available()=false; want true", name)
		}
	}
}

func TestErrRequiresLicenseIsWrappable(t *testing.T) {
	wrapped := errors.New("temporal posture query failed")
	joined := errors.Join(ErrRequiresLicense, wrapped)
	if !errors.Is(joined, ErrRequiresLicense) {
		t.Fatal("errors.Is could not detect ErrRequiresLicense through a wrap")
	}
}
