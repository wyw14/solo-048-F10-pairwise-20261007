package audit

import "time"

type Outcome string

const (
	OutcomeAccepted  Outcome = "accepted"
	OutcomeRejected  Outcome = "rejected"
	OutcomeCompleted Outcome = "completed"
	OutcomeFailed    Outcome = "failed"
)

// Severity classifies an audit entry independently of its outcome. It is
// either recorded explicitly or derived from the outcome (see
// SeverityFor), so every entry presented to clients carries one.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// SeverityFor maps an outcome to its default severity.
func SeverityFor(outcome Outcome) Severity {
	switch outcome {
	case OutcomeRejected:
		return SeverityWarning
	case OutcomeFailed:
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// ParseSeverity accepts the canonical severity strings; an empty string
// is the unset value and an unknown value is rejected.
func ParseSeverity(value string) (Severity, bool) {
	switch Severity(value) {
	case "":
		return "", true
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return Severity(value), true
	default:
		return "", false
	}
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

// Filter narrows an audit query. Empty values are unconstrained.
type Filter struct {
	// EntityID filters on the affected component/entity (主体).
	EntityID string
	// Action filters on the event type, e.g. "pump.stage" (事件类型).
	Action string
	// Outcome filters on the recorded outcome.
	Outcome Outcome
	// Severity filters on effective severity (explicit or derived).
	Severity Severity
	// Actor filters on the operator (操作人).
	Actor string
	// Since/Until bound entry time, both ends inclusive (按时间).
	Since time.Time
	Until time.Time
	// Limit is the page size; 0 means the query default.
	Limit int
}

// Match reports whether an entry passes every set filter dimension.
func (f Filter) Match(entry Entry) bool {
	if f.EntityID != "" && entry.EntityID != f.EntityID {
		return false
	}
	if f.Action != "" && entry.Action != f.Action {
		return false
	}
	if f.Outcome != "" && entry.Outcome != f.Outcome {
		return false
	}
	if f.Severity != "" && entry.Severity != f.Severity {
		return false
	}
	if f.Actor != "" && entry.Actor != f.Actor {
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
