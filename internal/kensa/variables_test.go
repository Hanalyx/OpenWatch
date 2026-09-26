// @spec api-system-scan-config
//
// VariableCatalog half of AC-08 (corpus-used intersection, placeholder
// flags, nil safety). Endpoint tests live in internal/server.
package kensa

import (
	"context"
	"os"
	"testing"

	pkgkensa "github.com/Hanalyx/kensa/pkg/kensa"
)

// corpusDir returns the dev corpus path or skips (same env the scan
// wiring uses; CI installs the module so `go list` resolves it, but
// unit tests use the env override to stay hermetic).
func corpusDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("OPENWATCH_KENSA_RULES_DIR")
	if dir == "" {
		t.Skip("set OPENWATCH_KENSA_RULES_DIR to run variable-catalog corpus tests")
	}
	return dir
}

// @ac AC-08
// AC-08 (catalog half): only corpus-used variables are listed, sorted,
// each with rules attributed; exactly the three placeholder names
// carry ConfigureMe; nil catalog is inert.
func TestVariableCatalog_CorpusUsedAndPlaceholders(t *testing.T) {
	t.Run("api-system-scan-config/AC-08", func(t *testing.T) {
		cat, err := NewVariableCatalog(corpusDir(t))
		if err != nil {
			t.Fatalf("NewVariableCatalog: %v", err)
		}
		list := cat.List()
		// The catalog is the corpus-used subset of kensa's built-ins
		// (C-07). The bound comes from the built-in table itself, so a
		// Kensa bump that adds variables does not break the test while a
		// catalog that lists a non-built-in still does.
		builtins, err := pkgkensa.BuiltInVars()
		if err != nil {
			t.Fatalf("BuiltInVars: %v", err)
		}
		if len(list) == 0 || len(list) > len(builtins) {
			t.Fatalf("catalog len = %d, want 1..%d (corpus-used subset of built-ins)", len(list), len(builtins))
		}
		for _, v := range list {
			if _, ok := builtins[v.Name]; !ok {
				t.Errorf("%s is listed but is not a kensa built-in variable", v.Name)
			}
		}
		flagged := 0
		for i, v := range list {
			if i > 0 && list[i-1].Name >= v.Name {
				t.Errorf("list not sorted: %q >= %q", list[i-1].Name, v.Name)
			}
			if len(v.Rules) == 0 {
				t.Errorf("%s: corpus-used variable with zero rules", v.Name)
			}
			if v.ConfigureMe {
				flagged++
				if !placeholderVars[v.Name] {
					t.Errorf("%s flagged ConfigureMe but is not a placeholder", v.Name)
				}
			}
			if !cat.Has(v.Name) {
				t.Errorf("Has(%s) = false for a listed variable", v.Name)
			}
		}
		// The three placeholders are corpus-used in the shipped rules.
		if flagged != 3 {
			t.Errorf("ConfigureMe count = %d, want 3 (rsyslog_remote_server, chrony_ntp_pool, banner_text)", flagged)
		}
		if cat.Has("definitely_not_a_variable") {
			t.Errorf("Has(unknown) = true")
		}

		var nilCat *VariableCatalog
		if nilCat.List() != nil || nilCat.Has("x") || nilCat.Len() != 0 {
			t.Errorf("nil catalog not inert")
		}
	})
}

// @ac AC-09
// AC-09 (reload half): varsFingerprint is order-independent and
// value-sensitive — the corpus cache reloads exactly when the
// effective override set changes.
func TestVarsFingerprint_StableAndValueSensitive(t *testing.T) {
	t.Run("api-system-scan-config/AC-09", func(t *testing.T) {
		a := map[string]string{"x": "1", "y": "2"}
		b := map[string]string{"y": "2", "x": "1"}
		if varsFingerprint(a) != varsFingerprint(b) {
			t.Errorf("fingerprint is order-sensitive")
		}
		c := map[string]string{"x": "1", "y": "CHANGED"}
		if varsFingerprint(a) == varsFingerprint(c) {
			t.Errorf("fingerprint missed a value change")
		}
		if varsFingerprint(nil) != "" || varsFingerprint(map[string]string{}) != "" {
			t.Errorf("empty set must fingerprint to the boot sentinel \"\"")
		}
	})
}

// @ac AC-11
// AC-11: a list-valued override reaches the rule's check parameters
// verbatim when the corpus reloads, and the built-in default returns when
// the override is removed. authorized_listening_ports ships with an empty
// default (Kensa v0.10.0), so its rule compares against nothing until an
// operator declares the set.
func TestCorpusReload_ListOverrideReachesCheck(t *testing.T) {
	t.Run("api-system-scan-config/AC-11", func(t *testing.T) {
		dir := corpusDir(t)
		rules, err := pkgkensa.LoadRules(dir, nil, nil)
		if err != nil {
			t.Fatalf("LoadRules: %v", err)
		}
		cache := &corpusCache{rules: rules, dir: dir}
		authorized := func(overrides map[string]string) []any {
			got := cache.current(context.Background(), func(context.Context) (map[string]string, error) {
				return overrides, nil
			})
			var vals []any
			for _, r := range got {
				if r.ID != "authorized-listening-ports" {
					continue
				}
				for _, impl := range r.Implementations {
					if impl.Check.Method == "set_compare" {
						vals = append(vals, impl.Check.Params["authorized"])
					}
				}
			}
			return vals
		}

		assertAll := func(label string, vals []any, want string) {
			t.Helper()
			if len(vals) == 0 {
				t.Fatalf("%s: rule authorized-listening-ports has no set_compare check", label)
			}
			for _, v := range vals {
				if v != want {
					t.Errorf("%s: authorized = %#v, want %q", label, v, want)
				}
			}
		}
		assertAll("default", authorized(nil), "")
		assertAll("override", authorized(map[string]string{"authorized_listening_ports": "22,443"}), "22,443")
		assertAll("override removed", authorized(map[string]string{}), "")
	})
}
