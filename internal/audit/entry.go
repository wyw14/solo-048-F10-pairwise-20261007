package audit

import "time"

type Outcome string

const (
	OutcomeAccepted  Outcome = "accepted"
	OutcomeRejected  Outcome = "rejected"
	OutcomeCompleted Outcome = "completed"
	OutcomeFailed    Outcome = "failed"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	}
	return false
}

type Entry struct {
	ID       string         `json:"id"`
	Action   string         `json:"action"`
	EntityID string         `json:"entity_id"`
	Actor    string         `json:"actor"`
	Outcome  Outcome        `json:"outcome"`
	Severity Severity       `json:"severity"`
	Message  string         `json:"message"`
	At       time.Time      `json:"at"`
	Details  map[string]any `json:"details,omitempty"`
}

type Filter struct {
	EntityID string
	Action   string
	Actor    string
	Outcome  Outcome
	Severity Severity
	// Since and Until bound the entry timestamp inclusively on both ends.
	// The zero value disables the corresponding bound.
	Since time.Time
	Until time.Time
	Limit int
}

func (f Filter) Match(entry Entry) bool {
	if f.EntityID != "" && entry.EntityID != f.EntityID {
		return false
	}
	if f.Action != "" && entry.Action != f.Action {
		return false
	}
	if f.Actor != "" && entry.Actor != f.Actor {
		return false
	}
	if f.Outcome != "" && entry.Outcome != f.Outcome {
		return false
	}
	if f.Severity != "" && entry.Severity != f.Severity {
		return false
	}
	if !f.Since.IsZero() && entry.At.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && entry.At.After(f.Until) {
		return false
	}
	return true
}
