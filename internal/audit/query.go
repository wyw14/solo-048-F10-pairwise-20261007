package audit

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"heatpulse/internal/store"
)

// DefaultPageSize and MaxPageSize bound unparameterized and oversized
// queries so a scan never has to walk the whole log into one response.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

var (
	// ErrCursor is returned when a continuation token cannot be decoded or
	// was not issued by this service.
	ErrCursor = errors.New("invalid pagination cursor")
	// ErrCursorFilter is returned when the filter on a paged request does
	// not match the filter the cursor was created with.
	ErrCursorFilter = errors.New("filter does not match pagination cursor")
	// ErrLogTruncated is returned when a cursor points past the end of the
	// log: the file was truncated/recreated after the cursor was issued, so
	// continuing from it could skip entries. Clients must restart at the
	// head.
	ErrLogTruncated = errors.New("audit log was truncated; pagination cursor is no longer valid")
)

// Query provides read access to audit entries over the shared event log.
type Query struct {
	log *store.EventLog
}

func NewQuery(log *store.EventLog) *Query {
	return &Query{log: log}
}

const auditKindPrefix = "audit."

// entryFromEvent converts a stored event into an audit Entry. Only
// audit.* events belong to the audit stream. The severity is read from
// the recorded fields and derived from the outcome for older records
// that predate the field.
func entryFromEvent(event store.Event) (Entry, bool) {
	if !strings.HasPrefix(event.Kind, auditKindPrefix) {
		return Entry{}, false
	}
	entry := Entry{
		ID:       event.ID,
		Action:   strings.TrimPrefix(event.Kind, auditKindPrefix),
		EntityID: event.EntityID,
		Message:  event.Message,
		At:       event.At,
		Details:  map[string]any{},
	}
	if actor, ok := event.Fields["actor"].(string); ok {
		entry.Actor = actor
	}
	if outcome, ok := event.Fields["outcome"].(string); ok {
		entry.Outcome = Outcome(outcome)
	}
	if severity, ok := event.Fields["severity"].(string); ok && severity != "" {
		entry.Severity = Severity(severity)
	} else {
		entry.Severity = SeverityFor(entry.Outcome)
	}
	if details, ok := event.Fields["details"].(map[string]any); ok && details != nil {
		entry.Details = details
	}
	return entry, true
}

// Gap marks a region of the log that could not be presented (corruption,
// a missing line, or a cursor anchor that no longer resolves).
type Gap struct {
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

// Page is one stable slice of the audit stream plus the information a
// client needs to continue and to notice holes.
type Page struct {
	Entries []Entry `json:"entries"`
	// NextCursor is opaque and empty when no older entries remain.
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
	// HasGaps is true when entries inside (or at the anchor of) this page
	// could not be read, so the caller knows the view is incomplete.
	HasGaps bool  `json:"has_gaps"`
	Gaps    []Gap `json:"gaps,omitempty"`
}

// cursorPayload is the JSON carried inside the opaque continuation token.
type cursorPayload struct {
	V      int    `json:"v"`
	Anchor int    `json:"anchor"` // physical log line the next page starts before
	Sig    string `json:"sig"`    // filter fingerprint
}

func (f Filter) normalizedLimit() int {
	switch {
	case f.Limit <= 0:
		return DefaultPageSize
	case f.Limit > MaxPageSize:
		return MaxPageSize
	default:
		return f.Limit
	}
}

// signature is a deterministic fingerprint of the filter dimensions that
// must stay constant across pages of one walk.
func (f Filter) signature() string {
	parts := [7]string{
		"e=" + f.EntityID,
		"a=" + f.Action,
		"o=" + string(f.Outcome),
		"s=" + string(f.Severity),
		"u=" + f.Actor,
		"from=" + formatCursorTime(f.Since),
		"to=" + formatCursorTime(f.Until),
	}
	return strings.Join(parts[:], "&")
}

func formatCursorTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func encodeCursor(anchor int, sig string) (string, error) {
	raw, err := json.Marshal(cursorPayload{V: 1, Anchor: anchor, Sig: sig})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeCursor(token, sig string) (int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrCursor, err)
	}
	var payload cursorPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.V != 1 || payload.Anchor <= 0 {
		return 0, fmt.Errorf("%w: malformed payload", ErrCursor)
	}
	if subtle.ConstantTimeCompare([]byte(payload.Sig), []byte(sig)) != 1 {
		return 0, ErrCursorFilter
	}
	return payload.Anchor, nil
}

// PageN returns the first (cursor == "") or a subsequent filtered page
// of audit entries, newest first. The cursor is anchored to a physical
// append position in the log, so entries appended after the walk began
// land above the first page and can never reappear on later pages or
// push already-read entries out of view.
func (q *Query) PageN(filter Filter, cursor string) (Page, error) {
	limit := filter.normalizedLimit()
	sig := filter.signature()

	anchor := 0
	if cursor != "" {
		var err error
		if anchor, err = decodeCursor(cursor, sig); err != nil {
			return Page{}, err
		}
	}

	keep := func(event store.Event) bool {
		entry, ok := entryFromEvent(event)
		if !ok {
			return false
		}
		return filter.Match(entry)
	}

	scan, err := q.log.ScanBefore(anchor, limit, keep)
	if err != nil {
		return Page{}, fmt.Errorf("scan audit log: %w", err)
	}
	if scan.AnchorBeyondLog {
		return Page{}, ErrLogTruncated
	}

	page := Page{
		Entries: make([]Entry, 0, len(scan.Events)),
		HasMore: scan.HasMore,
		Gaps:    make([]Gap, 0, len(scan.Gaps)),
	}
	for _, event := range scan.Events {
		entry, _ := entryFromEvent(event)
		page.Entries = append(page.Entries, entry)
	}
	for _, gap := range scan.Gaps {
		page.Gaps = append(page.Gaps, Gap{Line: gap.Line, Reason: gap.Reason})
	}
	if !scan.AnchorFound {
		// The continuation point recorded by the previous cursor has been
		// removed or corrupted: entries may be missing between pages.
		page.Gaps = append(page.Gaps, Gap{Line: anchor, Reason: "cursor anchor missing from log"})
	}
	page.HasGaps = len(page.Gaps) > 0
	if scan.HasMore {
		token, err := encodeCursor(scan.NextAnchor, sig)
		if err != nil {
			return Page{}, fmt.Errorf("encode cursor: %w", err)
		}
		page.NextCursor = token
	}
	return page, nil
}

// Recent returns up to filter.Limit newest matching entries (no cursor).
// Limit <= 0 means unbounded; it backs the summary view.
func (q *Query) Recent(filter Filter) ([]Entry, error) {
	events, err := q.log.List(0)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(events))
	for _, event := range events {
		entry, ok := entryFromEvent(event)
		if !ok {
			continue
		}
		if filter.Match(entry) {
			entries = append(entries, entry)
		}
		if filter.Limit > 0 && len(entries) >= filter.Limit {
			break
		}
	}
	return entries, nil
}

func (q *Query) Summary(since time.Time) (map[Outcome]int, error) {
	entries, err := q.Recent(Filter{})
	if err != nil {
		return nil, fmt.Errorf("query audit summary: %w", err)
	}
	counts := make(map[Outcome]int)
	for _, entry := range entries {
		if entry.At.Before(since) {
			continue
		}
		counts[entry.Outcome]++
	}
	return counts, nil
}
