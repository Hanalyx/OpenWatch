// Package reportschedule recurs report generation on a daily/weekly/monthly
// cadence and delivers the rendered PDF by email. A report_schedules row
// captures the report kind + scope, the cadence, and the email channel; the
// cron dispatcher (dispatcher.go) claims due schedules, generates the
// report, renders its PDF, emails it, and advances next_run_at.
//
// Spec: system-report-schedule.
package reportschedule

import (
	"time"

	"github.com/google/uuid"
)

// Frequency is the recurrence cadence.
type Frequency string

const (
	Daily   Frequency = "daily"
	Weekly  Frequency = "weekly"
	Monthly Frequency = "monthly"
)

// IsValid reports whether f is a supported cadence.
func (f Frequency) IsValid() bool {
	return f == Daily || f == Weekly || f == Monthly
}

// Scope mirrors the report GenerateRequest scope (stored as the schedule's
// scope JSONB): an optional group, framework lens, and period window.
type Scope struct {
	GroupID    *uuid.UUID `json:"group_id,omitempty"`
	Framework  string     `json:"framework,omitempty"`
	PeriodDays int        `json:"period_days,omitempty"`
}

// Schedule is one report_schedules row.
type Schedule struct {
	ID         uuid.UUID
	Name       string
	Kind       string
	Scope      Scope
	Frequency  Frequency
	Hour       int  // hour of day (UTC) to run
	Weekday    *int // 0=Sun..6=Sat, for weekly
	DayOfMonth *int // 1..28, for monthly
	ChannelID  uuid.UUID
	Enabled    bool
	NextRunAt  time.Time
	LastRunAt  *time.Time
	LastStatus string
	CreatedBy  *uuid.UUID
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// CreateParams is the input to Create.
type CreateParams struct {
	Name       string
	Kind       string
	Scope      Scope
	Frequency  Frequency
	Hour       int
	Weekday    *int
	DayOfMonth *int
	ChannelID  uuid.UUID
	CreatedBy  *uuid.UUID
}
