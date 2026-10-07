package audit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"heatpulse/internal/store"
)

const (
	// DefaultPageLimit applies when Filter.Limit is unset on a Page call.
	DefaultPageLimit = 50
	// MaxPageLimit caps a single page regardless of Filter.Limit.
	MaxPageLimit = 500
)

type Query struct {
	log *store.EventLog
}

func NewQuery(log *store.EventLog) *Query {
	return &Query{log: log}
}

// Page is one page of audit entries in newest-first order. NextCursor
// resumes the walk; Gap reports that continuity can no longer be
// guaranteed (see GapReason).
type Page struct {
	Entries    []Entry `json:"entries"`
	NextCursor string  `json:"next_cursor,omitempty"`
	HasMore    bool    `json:"has_more"`
	Gap        bool    `json:"gap"`
	GapReason  string  `json:"gap_reason,omitempty"`
}

// cursor is the opaque pagination position. Before is the keyset bound:
// only events with a smaller Seq are eligible, so events appended while
// the client pages can neither be returned twice nor push already-read
// events across the boundary. BeforeID anchors Before to a specific event
// so a rotated or rewritten log is detected instead of silently
// re-interpreted. High is the high-water Seq observed when the walk
// started, and MinAt the oldest timestamp returned so far; together they
// detect late events backfilled into the already-read time range.
type cursor struct {
	Before   uint64    `json:"before"`
	BeforeID string    `json:"before_id"`
	High     uint64    `json:"high"`
	MinAt    time.Time `json:"min_at,omitempty"`
}

func encodeCursor(position cursor) string {
	raw, err := json.Marshal(position)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCursor(value string) (cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return cursor{}, fmt.Errorf("invalid audit cursor")
	}
	var position cursor
	if err := json.Unmarshal(raw, &position); err != nil {
		return cursor{}, fmt.Errorf("invalid audit cursor")
	}
	return position, nil
}

// Page returns audit entries matching filter in newest-first order. Pass
// an empty cursor for the first page and Page.NextCursor for each
// following one. Events appended during the walk never appear in later
// pages and never displace events the walk has already returned.
func (q *Query) Page(filter Filter, after string) (Page, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = DefaultPageLimit
	}
	if limit > MaxPageLimit {
		limit = MaxPageLimit
	}

	events, err := q.log.List(0)
	if err != nil {
		return Page{}, err
	}

	position := cursor{Before: uint64(len(events))}
	if len(events) > 0 {
		position.High = uint64(len(events)) - 1
	}
	resumed := after != ""
	if resumed {
		decoded, err := decodeCursor(after)
		if err != nil {
			return Page{}, err
		}
		position = decoded
	}

	page := Page{Entries: []Entry{}}
	if resumed {
		page.Gap, page.GapReason = detectGap(events, position)
	}

	minAt := position.MinAt
	var lastSeq uint64
	var lastID string
	for _, event := range events {
		if event.Seq >= position.Before {
			continue
		}
		entry, ok := decodeEntry(event)
		if !ok || !filter.Match(entry) {
			continue
		}
		if len(page.Entries) >= limit {
			page.HasMore = true
			break
		}
		page.Entries = append(page.Entries, entry)
		lastSeq, lastID = event.Seq, event.ID
		if minAt.IsZero() || entry.At.Before(minAt) {
			minAt = entry.At
		}
	}
	if page.HasMore {
		page.NextCursor = encodeCursor(cursor{
			Before:   lastSeq,
			BeforeID: lastID,
			High:     position.High,
			MinAt:    minAt,
		})
	}
	return page, nil
}

// detectGap reports whether the walk described by position lost
// continuity: either the log changed underneath the cursor (rotation,
// truncation, rewrite), or events arrived after the walk started whose
// timestamps fall inside the range already returned to the client.
func detectGap(events []store.Event, position cursor) (bool, string) {
	anchored := false
	for _, event := range events {
		if event.Seq == position.Before {
			anchored = true
			if event.ID != position.BeforeID {
				return true, "event log changed since cursor was issued; entries may be missing or duplicated"
			}
			break
		}
	}
	if !anchored {
		return true, "event log rotated or truncated since cursor was issued; entries may be missing"
	}
	if !position.MinAt.IsZero() {
		for _, event := range events {
			if event.Seq > position.High && event.At.Before(position.MinAt) {
				return true, "new events fall inside the already-read time range"
			}
		}
	}
	return false, ""
}

func (q *Query) Recent(filter Filter) ([]Entry, error) {
	events, err := q.log.List(0)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(events))
	for _, event := range events {
		entry, ok := decodeEntry(event)
		if !ok || !filter.Match(entry) {
			continue
		}
		entries = append(entries, entry)
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

func decodeEntry(event store.Event) (Entry, bool) {
	if len(event.Kind) < len("audit.") || event.Kind[:len("audit.")] != "audit." {
		return Entry{}, false
	}
	entry := Entry{
		ID: event.ID, Action: event.Kind[len("audit."):], EntityID: event.EntityID,
		Message: event.Message, At: event.At, Details: map[string]any{},
	}
	if actor, ok := event.Fields["actor"].(string); ok {
		entry.Actor = actor
	}
	if outcome, ok := event.Fields["outcome"].(string); ok {
		entry.Outcome = Outcome(outcome)
	}
	if severity, ok := event.Fields["severity"].(string); ok {
		entry.Severity = Severity(severity)
	}
	if entry.Severity == "" {
		entry.Severity = SeverityInfo
	}
	return entry, true
}
