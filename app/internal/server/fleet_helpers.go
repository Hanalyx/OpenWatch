package server

import (
	"net/http"
	"time"

	"github.com/Hanalyx/openwatch/internal/fleetrollup"
)

// frameworkOpts produces the fleetrollup.Option list for the optional
// ?framework= query parameter. Nil or empty value returns no options
// (unfiltered). Spec api-fleet-observability v1.1.0 C-07 / C-08.
func frameworkOpts(framework *string) []fleetrollup.Option {
	if framework == nil || *framework == "" {
		return nil
	}
	return []fleetrollup.Option{fleetrollup.WithFramework(*framework)}
}

// validatePaginatedLimit reads the optional ?limit= parameter and
// returns the value to pass into fleetrollup. On nil it returns the
// default (50). On values outside [1, fleetrollup.MaxLimit] it writes
// a 400 pagination.limit_exceeded and returns (0, false).
//
// Spec api-fleet-observability AC-09, AC-10.
func validatePaginatedLimit(w http.ResponseWriter, raw *int) (int, bool) {
	if raw == nil {
		return 50, true
	}
	v := *raw
	if v < 1 || v > fleetrollup.MaxLimit {
		writeError(w, http.StatusBadRequest, "pagination.limit_exceeded", "client",
			"limit must be between 1 and 1000", false)
		return 0, false
	}
	return v, true
}

// nilOrTime dereferences a *time.Time or returns the zero value. The
// fleetrollup methods interpret time.Time{} as "no cursor".
func nilOrTime(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return *p
}
