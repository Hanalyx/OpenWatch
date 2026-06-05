// Package migrations embeds the SQL migration files and exposes the goose
// runner that applies them.
//
// Migrations are SQL-flavor goose files (annotations: `-- +goose Up`,
// `-- +goose Down`). Versioning is filename-based: NNNN_description.sql,
// where NNNN is a zero-padded ascending integer. Day-by-day day plan
// numbers don't drive the version; migration order does.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed *.sql
var fsys embed.FS

// FS returns the embedded migration filesystem (for goose).
func FS() fs.FS { return fsys }

// List returns the migration filenames in lexicographic order. Useful for
// diagnostics and tests.
func List() ([]string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("migrations: read dir: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}
