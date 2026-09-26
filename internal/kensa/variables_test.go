// @spec api-system-scan-config
//
// VariableCatalog half of AC-08 (corpus-used intersection, placeholder
// flags, nil safety). Endpoint tests live in internal/server.
package kensa

import (
	"context"
	"os"
	"reflect"
	"sort"
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
// AC-08 (catalog half): the catalog is exactly the corpus-used subset of
// kensa's built-ins, each entry carrying its built-in default and the
// sorted ids of the rules that use it; ConfigureMe marks exactly the
// variables the operator has to decide; nil catalog is inert.
func TestVariableCatalog_CorpusUsedAndPlaceholders(t *testing.T) {
	t.Run("api-system-scan-config/AC-08", func(t *testing.T) {
		dir := corpusDir(t)
		cat, err := NewVariableCatalog(dir)
		if err != nil {
			t.Fatalf("NewVariableCatalog: %v", err)
		}
		builtins, err := pkgkensa.BuiltInVars()
		if err != nil {
			t.Fatalf("BuiltInVars: %v", err)
		}
		used, err := pkgkensa.RuleVariables(dir)
		if err != nil {
			t.Fatalf("RuleVariables: %v", err)
		}

		// Contents, not only shape: the expected entries are built here from
		// the two library tables, and every listed entry must match one.
		want := map[string]VariableInfo{}
		for name, rules := range used {
			if _, ok := builtins[name]; !ok {
				continue
			}
			sorted := append([]string(nil), rules...)
			sort.Strings(sorted)
			want[name] = VariableInfo{Name: name, Default: builtins[name], Rules: sorted}
		}
		list := cat.List()
		if len(list) != len(want) {
			t.Errorf("catalog len = %d, want %d (corpus-used built-ins)", len(list), len(want))
		}
		for i, v := range list {
			if i > 0 && list[i-1].Name >= v.Name {
				t.Errorf("list not sorted: %q >= %q", list[i-1].Name, v.Name)
			}
			w, ok := want[v.Name]
			if !ok {
				t.Errorf("%s is listed but is not a corpus-used kensa built-in", v.Name)
				continue
			}
			if v.Default != w.Default {
				t.Errorf("%s default = %q, want %q", v.Name, v.Default, w.Default)
			}
			if !reflect.DeepEqual(v.Rules, w.Rules) {
				t.Errorf("%s rules = %v, want %v", v.Name, v.Rules, w.Rules)
			}
			if !cat.Has(v.Name) {
				t.Errorf("Has(%s) = false for a listed variable", v.Name)
			}
		}

		// Two fixed points, so a library change that moved both tables in
		// step would still be noticed.
		for name, rule := range map[string]string{
			"authorized_listening_ports": "authorized-listening-ports",
			"authorized_local_accounts":  "no-unauthorized-accounts",
		} {
			var got *VariableInfo
			for i := range list {
				if list[i].Name == name {
					got = &list[i]
				}
			}
			if got == nil || got.Default != "" || !reflect.DeepEqual(got.Rules, []string{rule}) {
				t.Errorf("%s = %+v, want an empty default used only by %s", name, got, rule)
			}
		}

		// ConfigureMe: exactly the inventory C-07 names for this corpus.
		var flagged []string
		for _, v := range list {
			if v.ConfigureMe {
				flagged = append(flagged, v.Name)
			}
		}
		if !reflect.DeepEqual(flagged, configureMeInventory) {
			t.Errorf("ConfigureMe set = %v\nwant (C-07 inventory) %v", flagged, configureMeInventory)
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

// configureMeInventory is the variable inventory api-system-scan-config
// C-07 names for the pinned corpus (Kensa v0.10.0): the three placeholder
// defaults and the eight variables Kensa ships with no value. A Kensa bump
// that changes the set fails AC-08 on purpose, so the inventory and the
// contract are reviewed together.
var configureMeInventory = []string{
	"authorized_listening_ports",
	"authorized_local_accounts",
	"authorized_network_protocols",
	"authorized_privileged_users",
	"authorized_service_accounts",
	"authorized_services",
	"banner_text",
	"chrony_ntp_pool",
	"flaw_remediation_max_days",
	"rsyslog_remote_server",
	"suid_sgid_baseline",
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
