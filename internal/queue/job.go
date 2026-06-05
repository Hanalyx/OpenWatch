// Package queue is the PostgreSQL-native async job queue. The Enqueue
// and Dequeue helpers are the only public surface that touches the
// job_queue table; lint forbids raw INSERT INTO job_queue elsewhere.
//
// Correlation propagation is built in: Enqueue extracts correlation_id
// from the caller's context (and errors if none is set); Dequeue
// restores the row's correlation_id onto a fresh worker context. See
// app/docs/correlation_id_propagation.md.
//
// Spec: app/specs/system/job-queue.spec.yaml.
package queue

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status is the queue-row lifecycle. Stored as text; CHECK constraint
// in 0003_job_queue.sql enforces the closed set.
type Status string

const (
	StatusPending    Status = "pending"
	StatusProcessing Status = "processing"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
)

// Job is the row shape exposed to consumers. Payload is opaque JSON.
type Job struct {
	ID            uuid.UUID
	JobType       string
	Payload       []byte // JSONB; opaque to the queue
	CorrelationID string
	Status        Status
	Attempts      int
	LastError     string
	CreatedAt     time.Time
	LockedAt      *time.Time
	CompletedAt   *time.Time
}

// ErrMissingCorrelation is returned by Enqueue when the caller's context
// has no correlation_id set. The queue rejects such jobs because every
// async unit must be traceable to its originating intent (HTTP request,
// cron tick, system boot).
//
// Spec system-job-queue AC-02, C-01.
var ErrMissingCorrelation = errors.New("queue: enqueue requires a correlation_id on context")

// ErrNoJob is returned by Dequeue when no pending job is available. Not
// fatal — workers poll on this.
var ErrNoJob = errors.New("queue: no pending job")
