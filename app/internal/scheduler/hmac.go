package scheduler

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
)

// JobPayload is the typed payload of a scheduler-enqueued scan job.
//
// Spec ACs satisfied here:
//
//   - AC-06 (C-06): a scheduler-enqueued job payload contains host_id,
//     framework_id, AND policy_version (snapshotted at enqueue time).
//   - C-11 / AC-15: the payload is signed with an HMAC over its canonical
//     byte representation; the dequeue path verifies before executing.
//     Tampered fields cause Verify to return false.
type JobPayload struct {
	// HostID identifies the target host (FK to hosts.id). Required.
	HostID uuid.UUID

	// FrameworkID is the compliance framework being scanned (e.g.,
	// "cis-rhel9-v2.0.0"). Required.
	FrameworkID string

	// PolicyVersion is the snapshot of policy.Schedules.Version at the
	// moment the job was enqueued. Reloads of the policy do not affect
	// this scan; threshold lookups use this version.
	PolicyVersion string

	// EnqueuedAt is the wall-clock time the scheduler enqueued the job.
	// Bound into the HMAC so a replayed-from-snapshot payload (recorded
	// from the queue and re-enqueued later) is rejected.
	EnqueuedAt time.Time
}

// QueueHMACSize is the size in bytes of the HMAC-SHA256 tag carried
// alongside each queued job payload. Constant so callers can size buffers
// without importing hmac/sha256 directly.
const QueueHMACSize = sha256.Size

// queueKeyHKDFInfo is the HKDF info string that binds the derived key
// to its purpose ("openwatch-queue-v1"). Changing this value invalidates
// every queued payload signed with the prior key; treat as a rotation
// boundary and bump the v1 → v2 suffix only with a migration plan.
const queueKeyHKDFInfo = "openwatch-queue-v1"

// queueKeySize is the size of the derived HMAC key (32 bytes — matches
// SHA-256's block size for maximum HMAC efficiency).
const queueKeySize = 32

// DeriveQueueKey derives a per-purpose HMAC key from the credential DEK
// using HKDF-SHA256.
//
// Per the open-question lean (option C): reusing the DEK for queue HMAC
// integrity is OK *as long as* the key is purpose-bound via HKDF info.
// HKDF guarantees keys derived for different info labels are
// independent, so a leak of the queue HMAC key does not enable
// credential decryption (and vice versa).
//
// Pure function — no I/O, no audit emission. Caller (cmd/openwatch/main.go
// at boot) caches the derived key for the lifetime of the process.
func DeriveQueueKey(dek []byte) ([]byte, error) {
	if len(dek) == 0 {
		return nil, errors.New("scheduler: cannot derive queue key from empty DEK")
	}
	// nil salt is acceptable; HKDF without salt reduces to an HMAC
	// construction which is still cryptographically sound for KDF use.
	// (Per RFC 5869 § 3.1: "if not provided, [salt] is set to a string
	// of HashLen zeros".)
	r, err := hkdf.Key(sha256.New, dek, nil, queueKeyHKDFInfo, queueKeySize)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Encode returns the canonical byte representation of the JobPayload.
// HMAC signs over this; both enqueue (Sign) and dequeue (Verify) paths
// MUST use this exact encoding so a stable HMAC is computed regardless
// of how the payload is otherwise serialized to JSONB on the queue row.
//
// Layout (big-endian throughout):
//
//	[0:16]   host_id (raw 16-byte UUID)
//	[16:20]  framework_id length (uint32)
//	[20:..]  framework_id bytes
//	[..:..]  policy_version length (uint32)
//	[..:..]  policy_version bytes
//	[..:..+8] enqueued_at as int64 Unix nanoseconds
func (p JobPayload) Encode() []byte {
	fid := []byte(p.FrameworkID)
	pv := []byte(p.PolicyVersion)

	// 16 (uuid) + 4 + len(fid) + 4 + len(pv) + 8 (unix nanos)
	size := 16 + 4 + len(fid) + 4 + len(pv) + 8
	buf := make([]byte, 0, size)

	buf = append(buf, p.HostID[:]...)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(fid))) //nolint:gosec // length is bounded by struct field size
	buf = append(buf, lenBuf...)
	buf = append(buf, fid...)

	binary.BigEndian.PutUint32(lenBuf, uint32(len(pv))) //nolint:gosec // length is bounded by struct field size
	buf = append(buf, lenBuf...)
	buf = append(buf, pv...)

	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(p.EnqueuedAt.UnixNano())) //nolint:gosec // intentional reinterpret for stable encoding
	buf = append(buf, tsBuf...)

	return buf
}

// Sign computes the HMAC-SHA256 tag of p.Encode() under the given key.
// Pure function; the same (key, payload) pair always produces the same tag.
func Sign(key []byte, p JobPayload) [QueueHMACSize]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(p.Encode()) // hmac.Write never returns a non-nil error
	var out [QueueHMACSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// Verify reports whether mac is a valid HMAC for p under key, using
// constant-time comparison to prevent timing-attack disclosure of the
// expected tag.
//
// Spec AC-15: a payload whose any signed field has been mutated post-
// enqueue produces a different canonical encoding, which produces a
// different HMAC, which Verify rejects. The dequeue path emits
// scheduler.job.hmac_rejected on a false return and increments
// Metrics.HMACRejectCount.
func Verify(key []byte, p JobPayload, mac [QueueHMACSize]byte) bool {
	expected := Sign(key, p)
	return subtle.ConstantTimeCompare(mac[:], expected[:]) == 1
}

// readFullDeterministic exists only to keep the hkdf.New return type
// usable without a separate io.Copy import; this helper is unused if
// hkdf.Key is available (Go 1.24+) but kept as a defensive fallback.
var _ = io.ReadFull
