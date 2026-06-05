package fleetrollup

// Option is a functional option for fleetrollup query methods.
// Spec api-fleet-observability v1.1.0 C-07/C-08, api-hosts v1.2.0 C-07/C-08.
type Option func(*queryOpts)

// queryOpts is the internal options bag.
type queryOpts struct {
	// framework, when non-empty, filters results to rows whose
	// framework_refs JSONB contains the given key. Empty string =
	// unfiltered (legacy v1.0.0 behavior).
	framework string
}

// WithFramework filters fleet aggregations and per-host queries to
// rows whose framework_refs JSONB contains the given key (e.g.,
// "cis_rhel9_v2.0.0"). Empty string is a no-op (unfiltered).
//
// The match is exact-key on the top-level JSONB object — no fuzzy
// matching, no case folding.
func WithFramework(framework string) Option {
	return func(o *queryOpts) {
		o.framework = framework
	}
}

// applyOpts collects opts into a queryOpts bag.
func applyOpts(opts []Option) queryOpts {
	var o queryOpts
	for _, fn := range opts {
		fn(&o)
	}
	return o
}
