//go:build ee

// EE build: licensed feature modules are compiled in. Once the ee/ tree exists,
// this file blank-imports it so the module's init registers implementations
// into internal/eereg:
//
//	import _ "github.com/Hanalyx/openwatch/ee"
//
// The import is intentionally absent in the scaffold — the ee/ tree does not
// exist yet — so the `-tags ee` build currently registers nothing and behaves
// identically to the CE build. The blank import lands in the same change that
// adds the first relocated feature (temporal_queries). This file being the only
// place that may import ee/ keeps the boundary auditable.
package main
