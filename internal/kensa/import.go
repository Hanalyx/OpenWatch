package kensa

// Blank-import the upstream Kensa API package. The internal/kensa
// wrapper does not yet call any kensa.* symbols directly (executor.go
// is a stub), but system-kensa-executor AC-10 requires
// github.com/Hanalyx/kensa to be pinned in app/go.mod as the
// authoritative version reference. Without an actual import in source,
// `go mod tidy` strips the line — which then collides with
// system-supply-chain AC-06 (tidy must be a no-op). This blank import
// is the smallest, lowest-risk way to satisfy both specs.
//
// When the executor wires up real Kensa calls, the blank import can
// be removed in favor of named symbol use.
import (
	_ "github.com/Hanalyx/kensa/api"
)
