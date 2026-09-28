// Framework display labels, from Kensa.
//
// Kensa owns the framework vocabulary, and pkg/kensa.FrameworkFromID carries
// its labels ("NIST SP 800-171 Rev 2", "CMMC Level 2", "CIS (RHEL 9)"). Every
// OpenWatch surface that names a framework takes its label from here, so one
// framework reads the same on every page and in every report, and 800-53,
// 800-171 and CMMC Level 2 stay distinguishable. An id Kensa does not know
// comes back verbatim: OpenWatch never invents a label.
//
// Spec: system-compliance-lens v1.7.0 (D-2 S-7).
package kensa

import (
	"sort"

	pkgkensa "github.com/Hanalyx/kensa/pkg/kensa"
)

// FrameworkLabel returns Kensa's display label for a framework id
// ("nist_800_171") or family ("cis"). Empty in, empty out.
func FrameworkLabel(id string) string {
	if id == "" {
		return ""
	}
	return pkgkensa.FrameworkFromID(id).Label
}

// FrameworkLabels returns the label for each distinct non-empty id.
func FrameworkLabels(ids []string) map[string]string {
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		if id != "" {
			out[id] = FrameworkLabel(id)
		}
	}
	return out
}

// FrameworkLabelsForRefs labels every framework id used as a key in the given
// framework_refs maps.
func FrameworkLabelsForRefs(refs ...map[string][]string) map[string]string {
	var ids []string
	for _, m := range refs {
		for id := range m {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return FrameworkLabels(ids)
}
