package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestLog(t *testing.T) *EventLog {
	t.Helper()
	return NewEventLog(filepath.Join(t.TempDir(), "events.jsonl"))
}

func appendTestEvent(t *testing.T, log *EventLog, kind string, at time.Time) {
	t.Helper()
	event := Event{ID: kind + "-" + strings.ReplaceAll(at.Format("150405.000000"), ".", ""), Kind: kind, EntityID: "ent", At: at}
	if err := log.Append(event); err != nil {
		t.Fatalf("append: %v", err)
	}
}

// writeRawLine appends a JSON event line bypassing seq allocation,
// emulating the pre-seq on-disk format.
func writeRawLine(path string, event Event) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(event)
}

// corruptLine rewrites a specific 1-based line in place, keeping the same
// number of lines so physical positions stay aligned.
func corruptLine(path string, lineNo int, replacement string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	if lineNo < 1 || lineNo > len(lines) {
		return os.ErrInvalid
	}
	lines[lineNo-1] = replacement
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func TestAppendAssignsMonotonicSeq(t *testing.T) {
	log := newTestLog(t)
	base := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	for i := 1; i <= 5; i++ {
		appendTestEvent(t, log, "audit.test", base.Add(time.Duration(i)*time.Second))
	}
	latest, err := log.LatestSeq()
	if err != nil {
		t.Fatal(err)
	}
	if latest != 5 {
		t.Fatalf("latest seq = %d, want 5", latest)
	}
	items, err := log.List(0)
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range items {
		if want := 5 - i; item.Seq != want { // List is newest-first
			t.Fatalf("position %d seq = %d, want %d", i, item.Seq, want)
		}
	}
}

func TestBootstrapSeqFromExistingLog(t *testing.T) {
	log := newTestLog(t)
	appendTestEvent(t, log, "audit.a", time.Now())
	appendTestEvent(t, log, "audit.b", time.Now())

	// A fresh handle over the same file must continue numbering at 3.
	relog := NewEventLog(log.path)
	appendTestEvent(t, relog, "audit.c", time.Now())
	items, _ := relog.List(0) // newest-first: c(3), b(2), a(1)
	want := []int{3, 2, 1}
	if len(items) != 3 {
		t.Fatalf("got %d items", len(items))
	}
	for i, item := range items {
		if item.Seq != want[i] {
			t.Fatalf("seqs = %v, want %v", seqValues(items), want)
		}
	}
}

func seqValues(items []Event) []int {
	out := make([]int, len(items))
	for i, item := range items {
		out[i] = item.Seq
	}
	return out
}

func TestLegacyLinesGetSyntheticPositions(t *testing.T) {
	log := newTestLog(t)
	for _, kind := range []string{"audit.old1", "audit.old2"} {
		if err := writeRawLine(log.path, Event{ID: kind, Kind: kind, EntityID: "ent", At: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	relog := NewEventLog(log.path)
	if latest, _ := relog.LatestSeq(); latest != 2 {
		t.Fatalf("legacy bootstrap latest = %d, want 2", latest)
	}
	appendTestEvent(t, relog, "audit.new", time.Now())
	items, _ := relog.List(0)
	if items[0].Seq != 3 || items[0].Kind != "audit.new" {
		t.Fatalf("post-legacy append = %+v", items[0])
	}
}

func TestPagingStableAcrossAppends(t *testing.T) {
	log := newTestLog(t)
	now := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	for i := 1; i <= 10; i++ {
		appendTestEvent(t, log, "audit.e", now.Add(time.Duration(i)*time.Second))
	}

	page1, err := log.ScanBefore(0, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page1.Events) != 3 || !page1.HasMore || page1.NextAnchor == 0 {
		t.Fatalf("bad page1: %+v", page1)
	}

	// New events land while the client walks later pages. They must not
	// appear in, nor shift, the in-flight traversal.
	for i := 11; i <= 14; i++ {
		appendTestEvent(t, log, "audit.e", now.Add(time.Duration(i)*time.Second))
	}

	var all []Event
	all = append(all, page1.Events...)
	anchor := page1.NextAnchor
	for page := 2; ; page++ {
		next, err := log.ScanBefore(anchor, 3, nil)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, next.Events...)
		anchor = next.NextAnchor
		if !next.HasMore {
			break
		}
	}

	if len(all) != 10 {
		t.Fatalf("walked %d entries, want the 10 originals (4 new writes must not leak)", len(all))
	}
	seen := map[int]bool{}
	for i, event := range all {
		if seen[event.Seq] {
			t.Fatalf("seq %d returned twice", event.Seq)
		}
		seen[event.Seq] = true
		if want := 10 - i; event.Seq != want {
			t.Fatalf("position %d seq = %d, want %d (order must be newest-first)", i, event.Seq, want)
		}
	}
}

func TestScanBeforeKeepFilterDoesNotShortenPage(t *testing.T) {
	log := newTestLog(t)
	now := time.Now()
	for i := 1; i <= 10; i++ {
		kind := "audit.keep"
		if i%2 == 0 {
			kind = "audit.drop"
		}
		appendTestEvent(t, log, kind, now.Add(time.Duration(i)*time.Second))
	}
	page, err := log.ScanBefore(0, 3, func(e Event) bool { return e.Kind == "audit.keep" })
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 3 {
		t.Fatalf("filtered page len = %d, want 3", len(page.Events))
	}
	for _, event := range page.Events {
		if event.Kind != "audit.keep" {
			t.Fatalf("non-matching event returned: %s", event.Kind)
		}
	}
	// 3 kept (lines 9,7,5) required scanning physical lines 10..5; the
	// next anchor is the oldest line reached, 5.
	if page.NextAnchor != 5 {
		t.Fatalf("next anchor = %d, want 5", page.NextAnchor)
	}
}

func TestScanBeforeCorruptLineReportedAsGap(t *testing.T) {
	log := newTestLog(t)
	appendTestEvent(t, log, "audit.a", time.Now())
	appendTestEvent(t, log, "audit.b", time.Now())
	appendTestEvent(t, log, "audit.c", time.Now())

	if err := corruptLine(log.path, 2, "{not json"); err != nil {
		t.Fatal(err)
	}
	page, err := NewEventLog(log.path).ScanBefore(0, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("decoded %d events around corrupt line, want 2", len(page.Events))
	}
	found := false
	for _, gap := range page.Gaps {
		if gap.Line == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("gap for line 2 not reported: %+v", page.Gaps)
	}
}

func TestAppendFailureRollsBackSeq(t *testing.T) {
	log := newTestLog(t)
	appendTestEvent(t, log, "audit.a", time.Now())
	// An existing regular file in MkdirAll's path forces a failure before
	// any line is written.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := NewEventLog(filepath.Join(blocker, "events.jsonl"))
	if err := bad.Append(Event{Kind: "audit.x", At: time.Now()}); err == nil {
		t.Fatal("expected append failure")
	}
	appendTestEvent(t, log, "audit.b", time.Now())
	items, _ := log.List(0)
	if items[0].Seq != 2 {
		t.Fatalf("seq after failed append = %d, want 2", items[0].Seq)
	}
}

// Sanity check: scanner tolerates the largest realistic audit line.
func TestLargeLine(t *testing.T) {
	log := newTestLog(t)
	big := strings.Repeat("x", 200_000)
	if err := log.Append(Event{Kind: "audit.big", EntityID: "ent", At: time.Now(), Fields: map[string]any{"m": big}}); err != nil {
		t.Fatal(err)
	}
	items, err := log.List(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items", len(items))
	}
}
