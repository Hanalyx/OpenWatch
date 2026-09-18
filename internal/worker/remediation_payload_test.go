package worker

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// @ac AC-17
// The initiating actor is part of what the HMAC covers, and its absence is
// the pre-1.7.0 wire shape rather than an error. A job cannot be
// re-attributed after enqueue, and a job queued before the field existed
// still verifies after the upgrade.
func TestRemediationPayload_ActorIsSignedAndOptional(t *testing.T) {
	t.Run("api-remediation/AC-17", func(t *testing.T) {
		key := []byte("0123456789abcdef0123456789abcdef") // pragma: allowlist secret
		base := RemediationPayload{
			RequestID: uuid.New(), HostID: uuid.New(), RuleID: "audit-sudo-log",
			Action: RemediationActionExecute,
		}
		alice, mallory := uuid.New(), uuid.New()

		// Signed with alice: the tag does not verify once alice is removed
		// or replaced.
		withAlice := base
		withAlice.ActorID = alice
		tag := signRemediation(key, withAlice)
		if !verifyRemediation(key, withAlice, tag) {
			t.Fatal("a payload with an actor must verify against its own tag")
		}
		stripped := withAlice
		stripped.ActorID = uuid.Nil
		if verifyRemediation(key, stripped, tag) {
			t.Error("removing the actor left the HMAC valid; the actor is not covered by the signature")
		}
		swapped := withAlice
		swapped.ActorID = mallory
		if verifyRemediation(key, swapped, tag) {
			t.Error("replacing the actor left the HMAC valid")
		}

		// The pre-1.7.0 shape: no actor_id key at all. Same bytes signed, so
		// a job queued by the previous release verifies unchanged.
		legacyBody := MarshalRemediationJob(key, base)
		if _, has := legacyBody["actor_id"]; has {
			t.Error("a payload with no actor must not emit an actor_id key")
		}
		raw, _ := json.Marshal(legacyBody)
		parsed, parsedTag, err := parseRemediationPayload(raw)
		if err != nil {
			t.Fatalf("parse legacy payload: %v", err)
		}
		if parsed.ActorID != uuid.Nil {
			t.Errorf("legacy payload parsed with actor %s; want none", parsed.ActorID)
		}
		if !verifyRemediation(key, parsed, parsedTag) {
			t.Error("a legacy payload no longer verifies")
		}

		// Round trip with an actor through the wire shape.
		body := MarshalRemediationJob(key, withAlice)
		if body["actor_id"] != alice.String() {
			t.Errorf("wire actor_id = %v, want %s", body["actor_id"], alice)
		}
		raw, _ = json.Marshal(body)
		parsed, parsedTag, err = parseRemediationPayload(raw)
		if err != nil {
			t.Fatalf("parse payload with actor: %v", err)
		}
		if parsed.ActorID != alice || !verifyRemediation(key, parsed, parsedTag) {
			t.Errorf("round trip lost or broke the actor: %s verify=%v", parsed.ActorID, verifyRemediation(key, parsed, parsedTag))
		}
		// Tampering with the wire actor_id after signing is caught.
		body["actor_id"] = mallory.String()
		raw, _ = json.Marshal(body)
		parsed, parsedTag, _ = parseRemediationPayload(raw)
		if verifyRemediation(key, parsed, parsedTag) {
			t.Error("a re-attributed job on the wire verified")
		}
	})
}
