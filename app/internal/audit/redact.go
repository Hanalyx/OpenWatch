package audit

import (
	"encoding/json"
	"strings"
)

// SensitiveFields enumerates the JSON keys that get scrubbed pre-write.
// Per app/docs/audit_event_taxonomy.md §6 and app/specs/system/audit-emission.spec.yaml
// AC-8, AC-9, AC-10.
//
// Lowercase comparison; matches are exact (no partial). Adding a field
// is one edit here; the field stays scrubbed across every emission site.
var SensitiveFields = map[string]struct{}{
	"password":    {},
	"ssh_key":     {},
	"api_key":     {},
	"token":       {},
	"secret":      {},
	"license_jwt": {},
}

// RedactedPlaceholder replaces sensitive values in the stored row.
const RedactedPlaceholder = "<REDACTED>"

// Redact scrubs sensitive keys in detail recursively. Returns the
// redacted JSON and the list of dotted-path field names that were
// scrubbed (e.g., "password" or "auth.password" for nested).
//
// Scrubs both top-level and nested object keys. Array indices in the
// path use bracket notation (e.g., "creds[0].password") so support can
// find the exact location.
//
// Behaviour preserved on malformed input: if the JSON can't be parsed,
// it's returned unchanged with an empty redactions slice — the event
// still writes (audit always wins) but flagged via the dropped metric.
func Redact(detail json.RawMessage) (json.RawMessage, []string) {
	if len(detail) == 0 {
		return detail, nil
	}

	var v interface{}
	if err := json.Unmarshal(detail, &v); err != nil {
		// Malformed — return as-is. Audit writer logs the parse failure.
		return detail, nil
	}

	var redacted []string
	v = walkRedact(v, "", &redacted)

	out, err := json.Marshal(v)
	if err != nil {
		// Should not happen — we just unmarshalled and walked.
		return detail, nil
	}
	return out, redacted
}

// walkRedact descends the parsed JSON tree, replacing values at sensitive
// keys and appending dotted paths to the redactions slice.
func walkRedact(v interface{}, path string, redactions *[]string) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			subPath := joinPath(path, k)
			if _, sensitive := SensitiveFields[strings.ToLower(k)]; sensitive {
				t[k] = RedactedPlaceholder
				*redactions = append(*redactions, subPath)
				continue
			}
			t[k] = walkRedact(child, subPath, redactions)
		}
		return t
	case []interface{}:
		for i, child := range t {
			subPath := path + "[" + indexStr(i) + "]"
			t[i] = walkRedact(child, subPath, redactions)
		}
		return t
	default:
		return v
	}
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// indexStr is a tiny int-to-string helper to avoid pulling in strconv
// for this one site. Acceptable for the index size range expected.
func indexStr(i int) string {
	if i == 0 {
		return "0"
	}
	const digits = "0123456789"
	// Build small-int representation in reverse.
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = digits[i%10]
		i /= 10
	}
	return string(buf[n:])
}
