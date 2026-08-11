package kensa

// Blank-import the upstream Kensa API package.
//
// This existed because the wrapper called no kensa symbols directly, so
// `go mod tidy` would strip the pin that system-kensa-executor AC-10
// requires. That condition ended: catalog.go, library.go, planfunc.go,
// remediatefunc.go, scanfunc.go and transport.go all import Kensa by
// name, and `go mod tidy` keeps the pin without this file. Verified
// 2026-08-06 by removing it and re-running tidy.
//
// It is therefore dead and can be deleted. Left in place only because
// removing it is a change AC-10 should be re-checked against first.
import (
	_ "github.com/Hanalyx/kensa/api"
)
