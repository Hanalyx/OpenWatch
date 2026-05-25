package policy

import (
	"sync/atomic"
	"time"
)

// current holds the active State pointer. Hot-path readers (Evaluate)
// load this atomically; loaders swap a fresh pointer on every successful
// LoadFile.
//
// Spec system-policy AC-07, C-03.
var current atomic.Pointer[State]

// Get returns the active state. Returns nil before Init runs.
//
// Spec system-policy AC-07.
func Get() *State {
	return current.Load()
}

// setState swaps the active pointer atomically. Internal; loaders call
// it after a successful parse+verify+validate.
func setState(s *State) {
	current.Store(s)
}

// Reset clears the active state. Used by tests for isolation. Production
// callers should use LoadFile / LoadEnvelope instead.
func Reset() {
	setState(nil)
}

// Init installs the built-in default state at version 0.0.0 for every
// recognized policy type. Idempotent — safe to call multiple times.
//
// Spec system-policy AC-01, C-04.
func Init() *State {
	s := &State{
		Versions: map[Type]string{
			TypeExceptions:      "0.0.0",
			TypeApprovals:       "0.0.0",
			TypeSchedules:       "0.0.0",
			TypeAlertThresholds: "0.0.0",
			TypeRemediation:     "0.0.0",
		},
		Sources: map[Type]string{
			TypeExceptions:      "default",
			TypeApprovals:       "default",
			TypeSchedules:       "default",
			TypeAlertThresholds: "default",
			TypeRemediation:     "default",
		},
		SignedBy: map[Type]string{
			TypeExceptions:      "default",
			TypeApprovals:       "default",
			TypeSchedules:       "default",
			TypeAlertThresholds: "default",
			TypeRemediation:     "default",
		},
		AlertThresholds: defaultAlertThresholds(),
		LoadedAt:        time.Now(),
	}
	setState(s)
	return s
}

// defaultAlertThresholds returns the built-in alert_thresholds policy
// at version 0.0.0. Values picked to match typical SCAP scoring norms:
// <50 = critical, <70 = high, <85 = medium, >=85 = ok.
func defaultAlertThresholds() AlertThresholds {
	return AlertThresholds{
		CriticalBelow: 50,
		HighBelow:     70,
		MediumBelow:   85,
	}
}
