// @spec system-audit-emission
//
// AC traceability:
// @ac AC-08  (TestRedact_TopLevelPassword)
// @ac AC-09  (TestRedact_AllSensitiveFields)
// @ac AC-10  (TestRedact_RecursesNested)

package audit

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// @ac AC-08  (A top-level password is scrubbed; redactions contains "password".)
func TestRedact_TopLevelPassword(t *testing.T) {
	t.Run("system-audit-emission/AC-08", func(t *testing.T) {

		in := json.RawMessage(`{"password":"hunter2","action":"login"}`)
		out, redactions := Redact(in)

		var got map[string]interface{}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if got["password"] != RedactedPlaceholder {
			t.Errorf("password not redacted: %v", got["password"])
		}
		if got["action"] != "login" {
			t.Errorf("non-sensitive field action altered: %v", got["action"])
		}
		if len(redactions) != 1 || redactions[0] != "password" {
			t.Errorf("redactions = %v, want [password]", redactions)
		}
	})
}

// @ac AC-09  (All six sensitive fields scrubbed; non-sensitive untouched.)
func TestRedact_AllSensitiveFields(t *testing.T) {
	t.Run("system-audit-emission/AC-09", func(t *testing.T) {

		in := json.RawMessage(`{
			"password":    "p",
			"ssh_key":     "k",
			"api_key":     "a",
			"token":       "t",
			"secret":      "s",
			"license_jwt": "l",
			"username":    "user1"
		}`)
		out, redactions := Redact(in)

		var got map[string]interface{}
		_ = json.Unmarshal(out, &got)

		for _, f := range []string{"password", "ssh_key", "api_key", "token", "secret", "license_jwt"} {
			if got[f] != RedactedPlaceholder {
				t.Errorf("%s not redacted: %v", f, got[f])
			}
		}
		if got["username"] != "user1" {
			t.Errorf("username altered: %v", got["username"])
		}

		want := []string{"api_key", "license_jwt", "password", "secret", "ssh_key", "token"}
		sort.Strings(redactions)
		if !reflect.DeepEqual(redactions, want) {
			t.Errorf("redactions = %v, want %v", redactions, want)
		}
	})
}

// @ac AC-10  (Nested object redaction; path uses dotted notation.)
func TestRedact_RecursesNested(t *testing.T) {
	t.Run("system-audit-emission/AC-10", func(t *testing.T) {

		in := json.RawMessage(`{"auth":{"password":"x","method":"oidc"},"actor":"alice"}`)
		out, redactions := Redact(in)

		var got map[string]interface{}
		_ = json.Unmarshal(out, &got)

		auth := got["auth"].(map[string]interface{})
		if auth["password"] != RedactedPlaceholder {
			t.Errorf("nested password not redacted: %v", auth["password"])
		}
		if auth["method"] != "oidc" {
			t.Errorf("non-sensitive nested field altered: %v", auth["method"])
		}
		if got["actor"] != "alice" {
			t.Errorf("sibling key altered: %v", got["actor"])
		}
		if len(redactions) != 1 || redactions[0] != "auth.password" {
			t.Errorf("redactions = %v, want [auth.password]", redactions)
		}
	})
}

// Bonus: array indices in the path.
func TestRedact_ArrayIndexInPath(t *testing.T) {
	in := json.RawMessage(`{"creds":[{"password":"a"},{"password":"b"}]}`)
	_, redactions := Redact(in)

	sort.Strings(redactions)
	want := []string{"creds[0].password", "creds[1].password"}
	if !reflect.DeepEqual(redactions, want) {
		t.Errorf("redactions = %v, want %v", redactions, want)
	}
}

// Bonus: empty input is a no-op.
func TestRedact_EmptyInput(t *testing.T) {
	out, redactions := Redact(nil)
	if out != nil {
		t.Errorf("Redact(nil) = %s, want nil", out)
	}
	if redactions != nil {
		t.Errorf("redactions = %v, want nil", redactions)
	}
}

// Bonus: malformed JSON is passed through unchanged (audit always wins).
func TestRedact_MalformedPassthrough(t *testing.T) {
	in := json.RawMessage(`{not valid`)
	out, redactions := Redact(in)
	if string(out) != string(in) {
		t.Errorf("malformed input modified: %s", out)
	}
	if redactions != nil {
		t.Errorf("redactions = %v, want nil", redactions)
	}
}
