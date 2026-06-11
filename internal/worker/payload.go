// JSONB payload parsing for scan jobs.
//
// The scheduler enqueues each scan job with a JSONB body of the shape:
//
//	{
//	  "host_id":        "<uuid>",
//	  "policy_version": "<string>",
//	  "enqueued_at":    "<RFC3339Nano timestamp>",
//	  "hmac":           "<hex-encoded sha256 tag>"
//	}
//
// The worker parses this back into scheduler.JobPayload + raw HMAC tag
// before any side effect (per system-worker-subcommand C-02).

package worker

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/scheduler"
)

// errMissingHMAC indicates the JSONB body has no "hmac" key. Treated as
// equivalent to an HMAC mismatch — dead-lettered with detail.failure =
// "payload_missing_hmac" (matching the existing scheduler.job.hmac_rejected
// detail enum already in audit/events.yaml).
var errMissingHMAC = errors.New("worker: scan job payload missing hmac")

// errMalformedPayload indicates the JSONB body could not be parsed at
// all (invalid JSON, missing required fields, malformed types).
// Treated as a permanent failure — dead-lettered, no retry, no
// host_backoff_state UPSERT (no host_id to key on).
var errMalformedPayload = errors.New("worker: scan job payload malformed")

// scanJobBody is the wire shape of the scheduler's enqueue body. Matches
// scheduler.Service's mustJSON map exactly — change either side, change
// both.
type scanJobBody struct {
	HostID        string `json:"host_id"`
	PolicyVersion string `json:"policy_version"`
	EnqueuedAt    string `json:"enqueued_at"`
	HMAC          string `json:"hmac"`
}

// parseScanPayload decodes the queue row's payload bytes into a
// scheduler.JobPayload and the raw HMAC tag for scheduler.Verify.
//
// Returns errMalformedPayload for any structural problem (invalid JSON,
// bad UUID, bad timestamp). Returns errMissingHMAC when every other
// field parses but the hmac key is missing or empty.
func parseScanPayload(raw []byte) (scheduler.JobPayload, [scheduler.QueueHMACSize]byte, error) {
	var zero [scheduler.QueueHMACSize]byte

	var body scanJobBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return scheduler.JobPayload{}, zero, fmt.Errorf("%w: unmarshal: %v", errMalformedPayload, err)
	}

	hostID, err := uuid.Parse(body.HostID)
	if err != nil {
		return scheduler.JobPayload{}, zero, fmt.Errorf("%w: host_id: %v", errMalformedPayload, err)
	}

	enqueuedAt, err := time.Parse(time.RFC3339Nano, body.EnqueuedAt)
	if err != nil {
		return scheduler.JobPayload{}, zero, fmt.Errorf("%w: enqueued_at: %v", errMalformedPayload, err)
	}

	if body.HMAC == "" {
		return scheduler.JobPayload{}, zero, errMissingHMAC
	}

	tagBytes, err := hex.DecodeString(body.HMAC)
	if err != nil {
		return scheduler.JobPayload{}, zero, fmt.Errorf("%w: hmac hex: %v", errMalformedPayload, err)
	}
	if len(tagBytes) != scheduler.QueueHMACSize {
		return scheduler.JobPayload{}, zero, fmt.Errorf("%w: hmac length: got %d want %d",
			errMalformedPayload, len(tagBytes), scheduler.QueueHMACSize)
	}
	var tag [scheduler.QueueHMACSize]byte
	copy(tag[:], tagBytes)

	return scheduler.JobPayload{
		HostID:        hostID,
		PolicyVersion: body.PolicyVersion,
		EnqueuedAt:    enqueuedAt,
	}, tag, nil
}
