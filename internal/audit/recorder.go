package audit

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"heatpulse/internal/store"
)

type Recorder struct {
	log *store.EventLog
}

func NewRecorder(log *store.EventLog) *Recorder {
	return &Recorder{log: log}
}

func (r *Recorder) Record(entry Entry) (Entry, error) {
	if entry.Action == "" || entry.EntityID == "" {
		return Entry{}, fmt.Errorf("audit action and entity are required")
	}
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	if entry.At.IsZero() {
		entry.At = time.Now().UTC()
	}
	if entry.Severity == "" {
		entry.Severity = SeverityFor(entry.Outcome)
	}
	event := store.Event{
		ID:       entry.ID,
		Kind:     "audit." + entry.Action,
		EntityID: entry.EntityID,
		Message:  entry.Message,
		At:       entry.At,
		Fields: map[string]any{
			"actor":    entry.Actor,
			"outcome":  entry.Outcome,
			"severity": entry.Severity,
			"details":  entry.Details,
		},
	}
	if err := r.log.Append(event); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

func (r *Recorder) Accepted(action, entityID, actor, message string, details map[string]any) error {
	_, err := r.Record(Entry{Action: action, EntityID: entityID, Actor: actor, Outcome: OutcomeAccepted, Message: message, Details: details})
	return err
}

func (r *Recorder) Rejected(action, entityID, actor, message string, details map[string]any) error {
	_, err := r.Record(Entry{Action: action, EntityID: entityID, Actor: actor, Outcome: OutcomeRejected, Message: message, Details: details})
	return err
}
