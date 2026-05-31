// @spec system-worker-subcommand
//
// AC traceability (this file):
//
//	(supports AC-02)  TestParseScanPayload_Valid_RoundTrip
//	(supports AC-02)  TestParseScanPayload_MissingHMAC
//	(supports AC-02)  TestParseScanPayload_MalformedJSON
//	(supports AC-02)  TestParseScanPayload_BadHMACLength

package worker

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/scheduler"
)

func makeScanBody(t *testing.T, hostID uuid.UUID, policyVersion string, enqueuedAt time.Time, key []byte) []byte {
	t.Helper()
	payload := scheduler.JobPayload{
		HostID:        hostID,
		PolicyVersion: policyVersion,
		EnqueuedAt:    enqueuedAt,
	}
	tag := scheduler.Sign(key, payload)
	body := map[string]any{
		"host_id":        payload.HostID.String(),
		"policy_version": payload.PolicyVersion,
		"enqueued_at":    payload.EnqueuedAt.UTC().Format(time.RFC3339Nano),
		"hmac":           hex.EncodeToString(tag[:]),
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestParseScanPayload_Valid_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	hostID := uuid.MustParse("01997d9d-6b8b-7222-9ab3-aaaaaaaaaaaa")
	enq := time.Now().UTC().Truncate(time.Nanosecond)
	body := makeScanBody(t, hostID, "v1", enq, key)

	got, tag, err := parseScanPayload(body)
	if err != nil {
		t.Fatalf("parseScanPayload: %v", err)
	}
	if got.HostID != hostID {
		t.Errorf("HostID = %v, want %v", got.HostID, hostID)
	}
	if got.PolicyVersion != "v1" {
		t.Errorf("PolicyVersion = %q, want v1", got.PolicyVersion)
	}
	if !got.EnqueuedAt.Equal(enq) {
		t.Errorf("EnqueuedAt = %v, want %v", got.EnqueuedAt, enq)
	}
	// The tag must verify against the same key.
	if !scheduler.Verify(key, got, tag) {
		t.Error("parsed payload + tag does not verify against the signing key")
	}
}

func TestParseScanPayload_MissingHMAC(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"host_id":        "01997d9d-6b8b-7222-9ab3-bbbbbbbbbbbb",
		"policy_version": "v1",
		"enqueued_at":    time.Now().UTC().Format(time.RFC3339Nano),
		// no "hmac"
	})
	_, _, err := parseScanPayload(body)
	if !errors.Is(err, errMissingHMAC) {
		t.Errorf("err = %v, want errMissingHMAC", err)
	}
}

func TestParseScanPayload_MalformedJSON(t *testing.T) {
	_, _, err := parseScanPayload([]byte("not json"))
	if !errors.Is(err, errMalformedPayload) {
		t.Errorf("err = %v, want errMalformedPayload", err)
	}
}

func TestParseScanPayload_BadHMACLength(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"host_id":        "01997d9d-6b8b-7222-9ab3-cccccccccccc",
		"policy_version": "v1",
		"enqueued_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"hmac":           hex.EncodeToString([]byte{1, 2, 3}), // wrong length
	})
	_, _, err := parseScanPayload(body)
	if !errors.Is(err, errMalformedPayload) {
		t.Errorf("err = %v, want errMalformedPayload (bad hmac length)", err)
	}
}
