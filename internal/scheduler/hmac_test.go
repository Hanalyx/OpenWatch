// @spec system-scheduler
//
// AC traceability (this file):
//   AC-06  TestJobPayload_HasRequiredFields
//          TestJobPayload_Encode_IncludesAllFields
//   AC-15  TestSignVerify_RoundTrip
//          TestVerify_TamperedHostID_Rejected
//          TestVerify_TamperedFramework_Rejected
//          TestVerify_TamperedPolicyVersion_Rejected
//          TestVerify_TamperedEnqueuedAt_Rejected
//          TestVerify_WrongKey_Rejected
//          TestDeriveQueueKey_Deterministic
//          TestDeriveQueueKey_DifferentDEKs_ProduceDifferentKeys
//          TestDeriveQueueKey_EmptyDEK_Errors

package scheduler

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fixedPayload returns a deterministic JobPayload used across tests so
// signatures are reproducible.
func fixedPayload() JobPayload {
	return JobPayload{
		HostID:        uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		PolicyVersion: "1.0.0",
		EnqueuedAt:    time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
	}
}

func testKey() []byte {
	// Fixed deterministic 32-byte test key; not a real secret.
	return []byte("0123456789abcdef0123456789abcdef") // pragma: allowlist secret
}

// @ac AC-06
// AC-06: the JobPayload struct exposes host_id, policy_version,
// enqueued_at (v2.0.0 — no FrameworkID). Reflection-checks both
// presence and absence.
func TestJobPayload_HasRequiredFields(t *testing.T) {
	t.Run("system-scheduler/AC-06", func(t *testing.T) {
		typ := reflect.TypeOf(JobPayload{})
		required := []struct {
			name string
			kind reflect.Kind
		}{
			{"HostID", reflect.Array}, // uuid.UUID is [16]byte
			{"PolicyVersion", reflect.String},
			{"EnqueuedAt", reflect.Struct}, // time.Time
		}
		for _, r := range required {
			f, ok := typ.FieldByName(r.name)
			if !ok {
				t.Errorf("JobPayload missing required field %q", r.name)
				continue
			}
			if f.Type.Kind() != r.kind {
				t.Errorf("JobPayload.%s: kind = %v, want %v", r.name, f.Type.Kind(), r.kind)
			}
		}
		// v2.0.0 AC-16 also enforced here: FrameworkID MUST NOT exist.
		if _, ok := typ.FieldByName("FrameworkID"); ok {
			t.Error("JobPayload still has FrameworkID field — v2.0.0 removed it (system-scheduler AC-16)")
		}
	})
}

// @ac AC-06
// AC-06: Encode includes every field, so mutating any of them changes
// the encoded bytes (and therefore the HMAC).
func TestJobPayload_Encode_IncludesAllFields(t *testing.T) {
	t.Run("system-scheduler/AC-06", func(t *testing.T) {
		base := fixedPayload()
		baseEnc := base.Encode()

		// Mutate each field; encoding must change for each.
		cases := []struct {
			name string
			mut  func(p *JobPayload)
		}{
			{"HostID", func(p *JobPayload) {
				p.HostID = uuid.MustParse("00000000-0000-0000-0000-000000000002")
			}},
			{"PolicyVersion", func(p *JobPayload) { p.PolicyVersion = "1.0.1" }},
			{"EnqueuedAt", func(p *JobPayload) { p.EnqueuedAt = p.EnqueuedAt.Add(time.Second) }},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				mutated := base
				c.mut(&mutated)
				if bytes.Equal(baseEnc, mutated.Encode()) {
					t.Errorf("Encode unchanged after mutating %s — field not in canonical encoding", c.name)
				}
			})
		}
	})
}

// @ac AC-15
// AC-15: Sign and Verify form a valid round-trip.
func TestSignVerify_RoundTrip(t *testing.T) {
	t.Run("system-scheduler/AC-15", func(t *testing.T) {
		key := testKey()
		p := fixedPayload()

		mac := Sign(key, p)
		if !Verify(key, p, mac) {
			t.Error("Verify rejected a signature produced by Sign — round-trip broken")
		}
	})
}

// @ac AC-15
// AC-15: A payload whose HostID has been mutated post-Sign fails
// verification. Models the threat where someone with DB write access to
// job_queue changes the target host_id between enqueue and dequeue.
func TestVerify_TamperedHostID_Rejected(t *testing.T) {
	t.Run("system-scheduler/AC-15", func(t *testing.T) {
		key := testKey()
		p := fixedPayload()
		mac := Sign(key, p)

		tampered := p
		tampered.HostID = uuid.MustParse("99999999-9999-9999-9999-999999999999")

		if Verify(key, tampered, mac) {
			t.Error("Verify accepted payload with mutated HostID; AC-15 broken")
		}
	})
}

// v2.0.0: TestVerify_TamperedFramework_Rejected removed. The
// FrameworkID field no longer exists in JobPayload; the scope-
// escalation threat it modeled (change framework post-enqueue)
// is now impossible because no framework identifier is carried on
// the wire. AC-15 retains coverage via TestVerify_TamperedHostID_Rejected
// and TestVerify_TamperedPolicyVersion_Rejected.

// @ac AC-15
// AC-15: tampered PolicyVersion fails verification (policy-bypass threat:
// change snapshot to a version with weaker thresholds after enqueue).
func TestVerify_TamperedPolicyVersion_Rejected(t *testing.T) {
	t.Run("system-scheduler/AC-15", func(t *testing.T) {
		key := testKey()
		p := fixedPayload()
		mac := Sign(key, p)

		tampered := p
		tampered.PolicyVersion = "0.0.1"

		if Verify(key, tampered, mac) {
			t.Error("Verify accepted payload with mutated PolicyVersion; AC-15 broken")
		}
	})
}

// @ac AC-15
// AC-15: tampered EnqueuedAt fails verification. Binding the timestamp
// prevents replay (re-enqueue a captured row at a later time).
func TestVerify_TamperedEnqueuedAt_Rejected(t *testing.T) {
	t.Run("system-scheduler/AC-15", func(t *testing.T) {
		key := testKey()
		p := fixedPayload()
		mac := Sign(key, p)

		tampered := p
		tampered.EnqueuedAt = tampered.EnqueuedAt.Add(time.Hour)

		if Verify(key, tampered, mac) {
			t.Error("Verify accepted payload with mutated EnqueuedAt; AC-15 broken")
		}
	})
}

// @ac AC-15
// AC-15 (defense in depth): a payload signed under one key cannot be
// verified under another. Models the rotation case where the queue
// HMAC key has been changed and old captured signatures stop validating.
func TestVerify_WrongKey_Rejected(t *testing.T) {
	t.Run("system-scheduler/AC-15", func(t *testing.T) {
		keyA := testKey()
		keyB := []byte("ZZZZZZZZ89abcdef0123456789abcdef") // different
		p := fixedPayload()

		mac := Sign(keyA, p)
		if Verify(keyB, p, mac) {
			t.Error("Verify accepted payload under wrong key; AC-15 broken")
		}
	})
}

// @ac AC-15
// AC-15: DeriveQueueKey is deterministic — same DEK in, same key out.
// Process restart with the same DEK produces the same queue key, so
// in-flight signed payloads continue to validate.
func TestDeriveQueueKey_Deterministic(t *testing.T) {
	t.Run("system-scheduler/AC-15", func(t *testing.T) {
		dek := []byte("deterministic-DEK-32-bytes-..xx!")

		k1, err := DeriveQueueKey(dek)
		if err != nil {
			t.Fatalf("derive #1: %v", err)
		}
		k2, err := DeriveQueueKey(dek)
		if err != nil {
			t.Fatalf("derive #2: %v", err)
		}
		if !bytes.Equal(k1, k2) {
			t.Errorf("DeriveQueueKey non-deterministic: k1=%x k2=%x", k1, k2)
		}
		if len(k1) != queueKeySize {
			t.Errorf("derived key length = %d, want %d", len(k1), queueKeySize)
		}
	})
}

// @ac AC-15
// AC-15: different DEKs produce different queue keys (HKDF is injective
// for fixed info+salt+length, so this is a sanity check on the derivation).
func TestDeriveQueueKey_DifferentDEKs_ProduceDifferentKeys(t *testing.T) {
	t.Run("system-scheduler/AC-15", func(t *testing.T) {
		k1, err := DeriveQueueKey([]byte("DEK-A-32-bytes-yes-yes-yes-yes-x"))
		if err != nil {
			t.Fatal(err)
		}
		k2, err := DeriveQueueKey([]byte("DEK-B-32-bytes-no-no-no-no-no-xx"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(k1, k2) {
			t.Error("different DEKs produced identical queue keys — HKDF derivation likely broken")
		}
	})
}

// @ac AC-15
// AC-15: an empty DEK is rejected. Production safeguard against booting
// with an unset OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE.
func TestDeriveQueueKey_EmptyDEK_Errors(t *testing.T) {
	t.Run("system-scheduler/AC-15", func(t *testing.T) {
		_, err := DeriveQueueKey(nil)
		if err == nil {
			t.Error("DeriveQueueKey with nil DEK should error, got nil")
		}
		_, err = DeriveQueueKey([]byte{})
		if err == nil {
			t.Error("DeriveQueueKey with empty DEK should error, got nil")
		}
	})
}
