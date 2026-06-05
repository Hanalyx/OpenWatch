package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ReloadDir scans dir for *.yaml files and runs LoadFile against each.
// Returns a per-type outcome map. Failures don't stop the iteration —
// each file is independent. Spec system-policy AC-11.
func ReloadDir(ctx context.Context, pool *pgxpool.Pool, dir string) (map[Type]LoadOutcome, error) {
	out := make(map[Type]LoadOutcome)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No policies dir → operator hasn't dropped any files. Built-in
			// defaults stay active.
			return out, nil
		}
		return out, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		stem := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
		outcome, _ := LoadFile(ctx, pool, path)
		out[Type(stem)] = outcome
	}
	return out, nil
}
