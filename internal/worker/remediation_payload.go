// JSONB payload + HMAC signing for remediation jobs.
//
// Mirrors the scan-job envelope (scheduler.JobPayload + hex HMAC tag), but the
// remediation payload carries its own load-bearing fields — request_id,
// rule_id, action, and (for rollback) txn_id — so it needs its own canonical
// encoding to HMAC-sign. We reuse the SAME queue key the scheduler derives
// (scheduler.DeriveQueueKey over the credential DEK); the encoding here is
// purpose-distinct from the scan encoding, so a scan tag can never validate a
// remediation payload and vice versa.
//
// The worker verifies the HMAC BEFORE any host-mutating side effect, exactly
// like the scan path (system-worker-subcommand C-02).
package worker

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// RemediationJobType is the queue.Job.JobType for a remediation execute or
// rollback. Distinct from ScanJobType so the dispatcher routes by type.
const RemediationJobType = "remediation"

// Remediation action discriminators carried in the payload.
const (
	RemediationActionExecute  = "execute"
	RemediationActionRollback = "rollback"
)

// remediationHMACDomain is prepended to the canonical encoding so a
// remediation tag is domain-separated from a scan tag even though both use the
// same key. Changing it is a key-rotation boundary.
const remediationHMACDomain = "openwatch-remediation-v1"

// RemediationPayload is the typed payload of a remediation job.
type RemediationPayload struct {
	RequestID uuid.UUID
	HostID    uuid.UUID
	RuleID    string
	Action    string    // execute | rollback
	TxnID     uuid.UUID // rollback only; uuid.Nil for execute
}

// remediationJobBody is the wire shape stored in the queue row's JSONB. Mirror
// of scanJobBody: string ids + hex hmac.
type remediationJobBody struct {
	RequestID string `json:"request_id"`
	HostID    string `json:"host_id"`
	RuleID    string `json:"rule_id"`
	Action    string `json:"action"`
	TxnID     string `json:"txn_id,omitempty"`
	HMAC      string `json:"hmac"`
}

// encodeRemediation returns the canonical byte representation the HMAC signs.
// Layout (big-endian lengths): domain || request_id || host_id || txn_id ||
// len(action) || action || len(rule_id) || rule_id. UUIDs are raw 16 bytes.
func encodeRemediation(p RemediationPayload) []byte {
	action := []byte(p.Action)
	rule := []byte(p.RuleID)
	buf := make([]byte, 0, len(remediationHMACDomain)+16*3+4+len(action)+4+len(rule))
	buf = append(buf, []byte(remediationHMACDomain)...)
	buf = append(buf, p.RequestID[:]...)
	buf = append(buf, p.HostID[:]...)
	buf = append(buf, p.TxnID[:]...)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(action))) //nolint:gosec // bounded by field
	buf = append(buf, lenBuf...)
	buf = append(buf, action...)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(rule))) //nolint:gosec // bounded by field
	buf = append(buf, lenBuf...)
	buf = append(buf, rule...)
	return buf
}

// signRemediation computes the HMAC-SHA256 tag of p under key.
func signRemediation(key []byte, p RemediationPayload) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(encodeRemediation(p))
	var out [sha256.Size]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// verifyRemediation reports whether tag is a valid HMAC for p under key
// (constant-time).
func verifyRemediation(key []byte, p RemediationPayload, tag [sha256.Size]byte) bool {
	expected := signRemediation(key, p)
	return subtle.ConstantTimeCompare(tag[:], expected[:]) == 1
}

// MarshalRemediationJob builds the signed JSONB body for queue.Enqueue. Used
// by the HTTP execute/rollback handlers so the worker can verify on claim.
func MarshalRemediationJob(key []byte, p RemediationPayload) map[string]any {
	tag := signRemediation(key, p)
	body := map[string]any{
		"request_id": p.RequestID.String(),
		"host_id":    p.HostID.String(),
		"rule_id":    p.RuleID,
		"action":     p.Action,
		"hmac":       fmt.Sprintf("%x", tag[:]),
	}
	if p.Action == RemediationActionRollback {
		body["txn_id"] = p.TxnID.String()
	}
	return body
}

var (
	errRemMissingHMAC   = errors.New("worker: remediation job payload missing hmac")
	errRemMalformed     = errors.New("worker: remediation job payload malformed")
	errRemUnknownAction = errors.New("worker: remediation job payload unknown action")
)

// parseRemediationPayload decodes a queue row's JSONB into a RemediationPayload
// + raw HMAC tag. Mirrors parseScanPayload's error taxonomy.
func parseRemediationPayload(raw []byte) (RemediationPayload, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	var body remediationJobBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return RemediationPayload{}, zero, fmt.Errorf("%w: unmarshal: %v", errRemMalformed, err)
	}
	requestID, err := uuid.Parse(body.RequestID)
	if err != nil {
		return RemediationPayload{}, zero, fmt.Errorf("%w: request_id: %v", errRemMalformed, err)
	}
	hostID, err := uuid.Parse(body.HostID)
	if err != nil {
		return RemediationPayload{}, zero, fmt.Errorf("%w: host_id: %v", errRemMalformed, err)
	}
	switch body.Action {
	case RemediationActionExecute, RemediationActionRollback:
	default:
		return RemediationPayload{}, zero, fmt.Errorf("%w: %q", errRemUnknownAction, body.Action)
	}
	p := RemediationPayload{
		RequestID: requestID,
		HostID:    hostID,
		RuleID:    body.RuleID,
		Action:    body.Action,
	}
	if body.Action == RemediationActionRollback {
		txnID, terr := uuid.Parse(body.TxnID)
		if terr != nil {
			return RemediationPayload{}, zero, fmt.Errorf("%w: txn_id: %v", errRemMalformed, terr)
		}
		p.TxnID = txnID
	}
	if body.HMAC == "" {
		return RemediationPayload{}, zero, errRemMissingHMAC
	}
	tagBytes, err := hex.DecodeString(body.HMAC)
	if err != nil {
		return RemediationPayload{}, zero, fmt.Errorf("%w: hmac hex: %v", errRemMalformed, err)
	}
	if len(tagBytes) != sha256.Size {
		return RemediationPayload{}, zero, fmt.Errorf("%w: hmac length: got %d want %d",
			errRemMalformed, len(tagBytes), sha256.Size)
	}
	var tag [sha256.Size]byte
	copy(tag[:], tagBytes)
	return p, tag, nil
}
