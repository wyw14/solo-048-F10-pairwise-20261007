package audit_test

import (
	"path/filepath"
	"testing"
	"time"

	"heatpulse/internal/audit"
	"heatpulse/internal/store"
)

func setup(t *testing.T) (*audit.Recorder, *audit.Query) {
	t.Helper()
	log := store.NewEventLog(filepath.Join(t.TempDir(), "events.jsonl"))
	return audit.NewRecorder(log), audit.NewQuery(log)
}

func record(t *testing.T, recorder *audit.Recorder, entry audit.Entry) audit.Entry {
	t.Helper()
	entry, err := recorder.Record(entry)
	if err != nil {
		t.Fatalf("record entry: %v", err)
	}
	return entry
}

func collectAll(t *testing.T, query *audit.Query, filter audit.Filter, pageSize int) ([]audit.Entry, []audit.Page) {
	t.Helper()
	filter.Limit = pageSize
	var entries []audit.Entry
	var pages []audit.Page
	cursor := ""
	for {
		page, err := query.Page(filter, cursor)
		if err != nil {
			t.Fatalf("page: %v", err)
		}
		entries = append(entries, page.Entries...)
		pages = append(pages, page)
		if !page.HasMore {
			return entries, pages
		}
		cursor = page.NextCursor
		if cursor == "" {
			t.Fatal("has_more is true but next cursor is empty")
		}
	}
}

func TestPageFilters(t *testing.T) {
	recorder, query := setup(t)
	base := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	record(t, recorder, audit.Entry{Action: "pump.stage", EntityID: "zone-a", Actor: "op-1", Severity: audit.SeverityInfo, At: base})
	record(t, recorder, audit.Entry{Action: "valve.manual", EntityID: "zone-a", Actor: "op-2", Severity: audit.SeverityWarning, At: base.Add(time.Hour)})
	record(t, recorder, audit.Entry{Action: "pump.stage", EntityID: "zone-b", Actor: "op-1", Severity: audit.SeverityCritical, At: base.Add(2 * time.Hour)})

	tests := []struct {
		name   string
		filter audit.Filter
		want   int
	}{
		{"by actor", audit.Filter{Actor: "op-1"}, 2},
		{"by severity", audit.Filter{Severity: audit.SeverityWarning}, 1},
		{"by action", audit.Filter{Action: "pump.stage"}, 2},
		{"since excludes earlier", audit.Filter{Since: base.Add(30 * time.Minute)}, 2},
		{"until excludes later", audit.Filter{Until: base.Add(30 * time.Minute)}, 1},
		{"time range", audit.Filter{Since: base.Add(30 * time.Minute), Until: base.Add(90 * time.Minute)}, 1},
		{"bounds inclusive", audit.Filter{Since: base, Until: base.Add(2 * time.Hour)}, 3},
		{"combined", audit.Filter{Actor: "op-1", Severity: audit.SeverityCritical}, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries, err := query.Recent(test.filter)
			if err != nil {
				t.Fatalf("recent: %v", err)
			}
			if len(entries) != test.want {
				t.Fatalf("got %d entries, want %d", len(entries), test.want)
			}
		})
	}
}

func TestPageStableUnderAppends(t *testing.T) {
	recorder, query := setup(t)
	base := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	original := make([]audit.Entry, 0, 5)
	for i := 0; i < 5; i++ {
		original = append(original, record(t, recorder, audit.Entry{
			Action: "pump.stage", EntityID: "zone-a", Actor: "op-1", At: base.Add(time.Duration(i) * time.Minute),
		}))
	}

	first, err := query.Page(audit.Filter{Limit: 2}, "")
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first.Entries) != 2 || !first.HasMore || first.Gap {
		t.Fatalf("unexpected first page: %+v", first)
	}

	// New events arrive while the client is between pages.
	for i := 0; i < 3; i++ {
		record(t, recorder, audit.Entry{
			Action: "valve.manual", EntityID: "zone-a", Actor: "op-2", At: base.Add(time.Hour).Add(time.Duration(i) * time.Minute),
		})
	}

	seen := map[string]bool{}
	for _, entry := range first.Entries {
		seen[entry.ID] = true
	}
	cursor := first.NextCursor
	for cursor != "" {
		page, err := query.Page(audit.Filter{Limit: 2}, cursor)
		if err != nil {
			t.Fatalf("page: %v", err)
		}
		if page.Gap {
			t.Fatalf("unexpected gap: %s", page.GapReason)
		}
		for _, entry := range page.Entries {
			if seen[entry.ID] {
				t.Fatalf("duplicate entry across pages: %s", entry.ID)
			}
			seen[entry.ID] = true
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}

	// Every original event was returned exactly once; the events appended
	// mid-walk never appeared in any page.
	if len(seen) != len(original) {
		t.Fatalf("got %d distinct entries, want %d", len(seen), len(original))
	}
	for _, entry := range original {
		if !seen[entry.ID] {
			t.Fatalf("original entry missing from walk: %s", entry.ID)
		}
	}
}

func TestPageNewestFirst(t *testing.T) {
	recorder, query := setup(t)
	base := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		record(t, recorder, audit.Entry{Action: "pump.stage", EntityID: "zone-a", At: base.Add(time.Duration(i) * time.Minute)})
	}
	entries, _ := collectAll(t, query, audit.Filter{}, 2)
	for i := 1; i < len(entries); i++ {
		if entries[i-1].At.Before(entries[i].At) {
			t.Fatalf("entries not newest-first at %d: %v then %v", i, entries[i-1].At, entries[i].At)
		}
	}
}

func TestPageGapOnRotation(t *testing.T) {
	recorder, query := setup(t)
	base := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		record(t, recorder, audit.Entry{Action: "pump.stage", EntityID: "zone-a", At: base.Add(time.Duration(i) * time.Minute)})
	}
	first, err := query.Page(audit.Filter{Limit: 2}, "")
	if err != nil {
		t.Fatalf("first page: %v", err)
	}

	// Rotate the log: the old file is replaced by a fresh, shorter one.
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	fresh := store.NewEventLog(logPath)
	rotated := audit.NewRecorder(fresh)
	record(t, rotated, audit.Entry{Action: "pump.stage", EntityID: "zone-b", At: base.Add(time.Hour)})
	rotatedQuery := audit.NewQuery(fresh)

	page, err := rotatedQuery.Page(audit.Filter{Limit: 2}, first.NextCursor)
	if err != nil {
		t.Fatalf("page after rotation: %v", err)
	}
	if !page.Gap {
		t.Fatal("expected gap after log rotation")
	}
}

func TestPageGapOnLateBackfill(t *testing.T) {
	recorder, query := setup(t)
	base := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		record(t, recorder, audit.Entry{Action: "pump.stage", EntityID: "zone-a", At: base.Add(time.Duration(i) * time.Minute)})
	}
	first, err := query.Page(audit.Filter{Limit: 2}, "")
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if first.Gap {
		t.Fatal("unexpected gap on first page")
	}

	// An event is backfilled with a timestamp older than the oldest entry
	// the first page already returned.
	record(t, recorder, audit.Entry{Action: "valve.manual", EntityID: "zone-a", At: base.Add(30 * time.Second)})

	page, err := query.Page(audit.Filter{Limit: 2}, first.NextCursor)
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if !page.Gap {
		t.Fatal("expected gap for backfilled event in already-read range")
	}
}

func TestPageRejectsInvalidCursor(t *testing.T) {
	_, query := setup(t)
	if _, err := query.Page(audit.Filter{}, "not-a-cursor"); err == nil {
		t.Fatal("expected error for invalid cursor")
	}
}

func TestPageLimitCap(t *testing.T) {
	recorder, query := setup(t)
	base := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		record(t, recorder, audit.Entry{Action: "pump.stage", EntityID: "zone-a", At: base.Add(time.Duration(i) * time.Minute)})
	}
	page, err := query.Page(audit.Filter{Limit: 100000}, "")
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if len(page.Entries) != 10 || page.HasMore {
		t.Fatalf("got %d entries hasMore=%v, want 10 entries hasMore=false", len(page.Entries), page.HasMore)
	}
}

