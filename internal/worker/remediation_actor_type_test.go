// @spec system-audit-emission
//
//	AC-25  TestRemediationPayload_ActorTypeIsSignedAndLegacyMeansUser
//
// bugs/OW-100: the remediation worker recorded every job's actor as a user,
// so a token's execute or rollback was typed user. The payload now carries
// the actor type, signed.
package worker

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// @ac AC-25
func TestRemediationPayload_ActorTypeIsSignedAndLegacyMeansUser(t *testing.T) {
	t.Run("system-audit-emission/AC-25", func(t *testing.T) {
		key := []byte("0123456789abcdef0123456789abcdef") // pragma: allowlist secret
		base := RemediationPayload{
			RequestID: uuid.New(), HostID: uuid.New(), RuleID: "audit-sudo-log",
			Action: RemediationActionExecute, ActorID: uuid.New(),
		}

		// A token's job: signed with its type; the type cannot be stripped
		// or swapped for user without breaking the tag.
		tok := base
		tok.ActorType = audit.ActorAPIKey
		tag := signRemediation(key, tok)
		if !verifyRemediation(key, tok, tag) {
			t.Fatal("a payload with an actor type must verify against its own tag")
		}
		stripped := tok
		stripped.ActorType = ""
		if verifyRemediation(key, stripped, tag) {
			t.Error("removing the actor type left the HMAC valid")
		}
		relabeled := tok
		relabeled.ActorType = audit.ActorUser
		if verifyRemediation(key, relabeled, tag) {
			t.Error("relabeling the token's job as a user left the HMAC valid")
		}

		// The wire round trip keeps the type, and the worker attributes the
		// job to the token as api_key.
		body := MarshalRemediationJob(key, tok)
		raw := mustMarshal(t, body)
		parsed, ptag, err := parseRemediationPayload(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if !verifyRemediation(key, parsed, ptag) {
			t.Fatal("parsed token payload does not verify")
		}
		if a := payloadActor(parsed); a.Type != audit.ActorAPIKey || a.ID != tok.ActorID.String() {
			t.Errorf("payloadActor = %+v, want api_key/%s", a, tok.ActorID)
		}

		// A payload signed before actor_type existed still verifies, and
		// means a user, which is what it always meant.
		legacy := base
		ltag := signRemediation(key, legacy)
		lraw := mustMarshal(t, MarshalRemediationJob(key, legacy))
		lparsed, lptag, err := parseRemediationPayload(lraw)
		if err != nil || !verifyRemediation(key, lparsed, lptag) || lptag != ltag {
			t.Fatalf("legacy payload no longer verifies: err=%v", err)
		}
		if a := payloadActor(lparsed); a.Type != audit.ActorUser {
			t.Errorf("legacy payloadActor type = %q, want user", a.Type)
		}

		// No actor id is system work.
		sys := base
		sys.ActorID = uuid.Nil
		if a := payloadActor(sys); a.Type != audit.ActorSystem {
			t.Errorf("no-actor payloadActor = %+v, want system", a)
		}
	})
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
