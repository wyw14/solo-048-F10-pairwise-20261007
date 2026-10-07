package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"heatpulse/internal/store"
)

func newTestQuery(t *testing.T) (*Query, *Recorder, *store.EventLog, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	log := store.NewEventLog(path)
	return NewQuery(log), NewRecorder(log), log, path
}

func mustRecord(t *testing.T, r *Recorder, entry Entry) Entry {
	t.Helper()
	recorded, err := r.Record(entry)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	return recorded
}

func TestSeverityDerivedFromOutcome(t *testing.T) {
	_, recorder, _, _ := newTestQuery(t)
	cases := map[Outcome]Severity{
		OutcomeAccepted:  SeverityInfo,
		OutcomeCompleted: SeverityInfo,
		OutcomeRejected:  SeverityWarning,
		OutcomeFailed:    SeverityCritical,
	}
	for outcome, want := range cases {
		entry := mustRecord(t, recorder, Entry{Action: "x", EntityID: "e", Outcome: outcome})
		if entry.Severity != want {
			t.Fatalf("outcome %s severity = %s, want %s", outcome, entry.Severity, want)
		}
	}
	explicit := mustRecord(t, recorder, Entry{Action: "x", EntityID: "e", Outcome: OutcomeAccepted, Severity: SeverityCritical})
	if explicit.Severity != SeverityCritical {
		t.Fatalf("explicit severity not preserved: %s", explicit.Severity)
	}
}

func TestFilters(t *testing.T) {
	query, recorder, _, _ := newTestQuery(t)
	base := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	mustRecord(t, recorder, Entry{Action: "pump.stage", EntityID: "zone-a", Actor: "alice", Outcome: OutcomeAccepted, At: base})
	mustRecord(t, recorder, Entry{Action: "pump.stage", EntityID: "zone-b", Actor: "bob", Outcome: OutcomeRejected, At: base.Add(time.Hour)})
	mustRecord(t, recorder, Entry{Action: "valve.open", EntityID: "zone-a", Actor: "alice", Outcome: OutcomeFailed, At: base.Add(2 * time.Hour)})

	cases := []struct {
		name   string
		filter Filter
		want   int
	}{
		{"actor", Filter{Actor: "alice"}, 2},
		{"entity", Filter{EntityID: "zone-a"}, 2},
		{"action", Filter{Action: "pump.stage"}, 2},
		{"outcome", Filter{Outcome: OutcomeAccepted}, 1},
		{"severity warning", Filter{Severity: SeverityWarning}, 1},
		{"severity critical", Filter{Severity: SeverityCritical}, 1},
		{"since", Filter{Since: base.Add(90 * time.Minute)}, 1},
		{"until", Filter{Until: base.Add(30 * time.Minute)}, 1},
		{"window", Filter{Since: base.Add(-time.Minute), Until: base.Add(90 * time.Minute)}, 2},
		{"combined", Filter{EntityID: "zone-a", Actor: "alice", Severity: SeverityCritical}, 1},
		{"no match", Filter{Actor: "carol"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := query.PageN(tc.filter, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Entries) != tc.want {
				t.Fatalf("got %d entries, want %d (%+v)", len(page.Entries), tc.want, page.Entries)
			}
		})
	}
}

func TestPaginationNoDuplicatesOrGapsAcrossAppends(t *testing.T) {
	query, recorder, _, _ := newTestQuery(t)
	base := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 7; i++ {
		mustRecord(t, recorder, Entry{Action: "pump.stage", EntityID: "z", Actor: "a", Outcome: OutcomeAccepted, At: base.Add(time.Duration(i) * time.Minute)})
	}
	// Non-audit events share the log and must never appear.
	if err := recorder.log.Append(store.Event{Kind: "telemetry.sample", EntityID: "z", At: base}); err != nil {
		t.Fatal(err)
	}

	page, err := query.PageN(Filter{Limit: 3}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 3 || page.NextCursor == "" {
		t.Fatalf("bad first page: %+v", page)
	}

	// Writes land (including a non-audit event) while paging is in flight.
	for i := 7; i < 10; i++ {
		mustRecord(t, recorder, Entry{Action: "pump.stage", EntityID: "z", Actor: "a", Outcome: OutcomeAccepted, At: base.Add(time.Duration(i) * time.Minute)})
	}

	var walked []Entry
	walked = append(walked, page.Entries...)
	cursor := page.NextCursor
	pages := 1
	for cursor != "" {
		next, err := query.PageN(Filter{Limit: 3}, cursor)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		walked = append(walked, next.Entries...)
		cursor = next.NextCursor
	}

	if len(walked) != 7 {
		t.Fatalf("walked %d audit entries, want exactly the 7 visible when the walk began", len(walked))
	}
	seen := map[string]bool{}
	var lastAt time.Time
	for i, entry := range walked {
		if seen[entry.ID] {
			t.Fatalf("entry %s returned twice", entry.ID)
		}
		seen[entry.ID] = true
		if i > 0 && entry.At.After(lastAt) {
			t.Fatalf("page %d broke newest-first ordering", pages)
		}
		lastAt = entry.At
	}
}

func TestPaginationFilteredSkipsDoNotStall(t *testing.T) {
	query, recorder, _, _ := newTestQuery(t)
	for i := 0; i < 6; i++ {
		actor := "alice"
		if i%2 == 0 {
			actor = "bob"
		}
		mustRecord(t, recorder, Entry{Action: "a", EntityID: "e", Actor: actor, Outcome: OutcomeAccepted})
	}
	filter := Filter{Actor: "bob", Limit: 2}
	page, err := query.PageN(filter, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("filtered page len = %d, want 2", len(page.Entries))
	}
	page2, err := query.PageN(filter, page.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2.Entries) != 1 || page2.NextCursor != "" {
		t.Fatalf("second filtered page = %+v", page2)
	}
}

func TestCursorRejectsTamperingAndFilterChange(t *testing.T) {
	query, recorder, _, _ := newTestQuery(t)
	mustRecord(t, recorder, Entry{Action: "a", EntityID: "e", Actor: "alice", Outcome: OutcomeAccepted})
	mustRecord(t, recorder, Entry{Action: "a", EntityID: "e", Actor: "bob", Outcome: OutcomeAccepted})
	mustRecord(t, recorder, Entry{Action: "a", EntityID: "e", Actor: "alice", Outcome: OutcomeAccepted})

	page, err := query.PageN(Filter{Actor: "alice", Limit: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := query.PageN(Filter{Actor: "alice", Limit: 1}, "not-a-cursor"); !errors.Is(err, ErrCursor) {
		t.Fatalf("tampered cursor err = %v, want ErrCursor", err)
	}
	if _, err := query.PageN(Filter{Actor: "bob", Limit: 1}, page.NextCursor); !errors.Is(err, ErrCursorFilter) {
		t.Fatalf("filter change err = %v, want ErrCursorFilter", err)
	}
}

func TestGapReportedForCorruptLine(t *testing.T) {
	query, recorder, _, log := newTestQuery(t)
	for i := 0; i < 4; i++ {
		mustRecord(t, recorder, Entry{Action: "a", EntityID: "e", Outcome: OutcomeAccepted})
	}
	// Corrupt line 2 while keeping the line count intact.
	content, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	lines[1] = "{broken"
	if err := os.WriteFile(log, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	page, err := query.PageN(Filter{Limit: 50}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !page.HasGaps {
		t.Fatalf("expected HasGaps, got %+v", page)
	}
	if len(page.Entries) != 3 {
		t.Fatalf("decoded %d entries around gap, want 3", len(page.Entries))
	}
}

func TestTruncatedCursorRejected(t *testing.T) {
	query, recorder, _, log := newTestQuery(t)
	for i := 0; i < 6; i++ {
		mustRecord(t, recorder, Entry{Action: "a", EntityID: "e", Outcome: OutcomeAccepted})
	}
	page, err := query.PageN(Filter{Limit: 2}, "")
	if err != nil {
		t.Fatal(err)
	}
	// Truncate the log to fewer lines than the cursor's anchor.
	content, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	if err := os.WriteFile(log, []byte(lines[0]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := query.PageN(Filter{Limit: 2}, page.NextCursor); !errors.Is(err, ErrLogTruncated) {
		t.Fatalf("truncated log err = %v, want ErrLogTruncated", err)
	}
}

func TestLegacyEntriesWithoutSeverityDeriveIt(t *testing.T) {
	query, _, eventLog, _ := newTestQuery(t)
	if err := eventLog.Append(store.Event{
		Kind: "audit.valve.open", EntityID: "e", At: time.Now(),
		Fields: map[string]any{"actor": "a", "outcome": string(OutcomeFailed)},
	}); err != nil {
		t.Fatal(err)
	}
	page, err := query.PageN(Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Severity != SeverityCritical {
		t.Fatalf("legacy severity = %+v", page.Entries)
	}
}
