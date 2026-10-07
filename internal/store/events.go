package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	// Seq is the 1-based monotonic sequence number assigned at append
	// time. On an intact log it equals the physical JSONL line number,
	// which makes it a stable pagination anchor: appends only ever add
	// higher values, so a page boundary expressed as a seq never shifts
	// under new writes. A zero value denotes a legacy line written before
	// Seq existed; such lines receive a synthetic seq equal to their line
	// number at read time.
	Seq      int            `json:"seq,omitempty"`
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	EntityID string         `json:"entity_id"`
	Message  string         `json:"message"`
	At       time.Time      `json:"at"`
	Fields   map[string]any `json:"fields,omitempty"`
}

// Gap describes a region of the on-disk log that could not be read as a
// valid event (corruption, truncated write, duplicate or missing seq).
type Gap struct {
	// Line is the 1-based log position: the physical JSONL line number
	// for a corrupt/duplicate line, or the missing seq when events jump.
	Line int `json:"line"`
	// Reason explains why the region is treated as a gap.
	Reason string `json:"reason"`
}

// linePos is one physical line of the log: either a decoded event or a
// marker for a line that could not be decoded safely.
type linePos struct {
	lineNo int
	event  *Event
	reason string // empty for a healthy event line
}

type EventLog struct {
	path    string
	mu      sync.Mutex
	lastSeq int // highest Seq assigned; bootstrapped from disk on first use
}

func NewEventLog(path string) *EventLog {
	return &EventLog{path: path}
}

func (l *EventLog) readLines() ([][]byte, error) {
	file, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return [][]byte{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open event log: %w", err)
	}
	defer file.Close()
	lines := make([][]byte, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 8192), 1024*1024)
	for scanner.Scan() {
		// Copy: scanner.Bytes() is reused between iterations.
		lines = append(lines, append([]byte(nil), scanner.Bytes()...))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan event log: %w", err)
	}
	return lines, nil
}

// loadLocked decodes every physical line in append order. Corrupt or
// duplicate-seq lines become marker positions instead of aborting the
// read. lastPos is the highest occupied position and is the baseline for
// future seq allocation.
func (l *EventLog) loadLocked() (positions []linePos, lastPos int, err error) {
	rawLines, err := l.readLines()
	if err != nil {
		return nil, 0, err
	}
	positions = make([]linePos, 0, len(rawLines))
	seen := make(map[int]struct{}, len(rawLines))
	for index, raw := range rawLines {
		lineNo := index + 1
		pos := linePos{lineNo: lineNo}
		var event Event
		if decodeErr := json.Unmarshal(raw, &event); decodeErr != nil {
			pos.reason = "corrupt line: " + decodeErr.Error()
			positions = append(positions, pos)
			continue
		}
		if event.Seq == 0 {
			event.Seq = lineNo // legacy line: position == line number
		} else if _, dup := seen[event.Seq]; dup {
			pos.reason = fmt.Sprintf("duplicate seq %d", event.Seq)
			positions = append(positions, pos)
			continue
		}
		seen[event.Seq] = struct{}{}
		pos.event = &event
		positions = append(positions, pos)
	}
	// On an append-only log every seq equals its physical line number;
	// the physical line count is therefore the next seq baseline.
	lastPos = len(rawLines)
	return positions, lastPos, nil
}

func (l *EventLog) bootstrapLocked() error {
	if l.lastSeq > 0 {
		return nil
	}
	_, lastPos, err := l.loadLocked()
	if err != nil {
		return err
	}
	l.lastSeq = lastPos
	return nil
}

func (l *EventLog) Append(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.bootstrapLocked(); err != nil {
		return fmt.Errorf("bootstrap event log: %w", err)
	}
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	l.lastSeq++
	event.Seq = l.lastSeq

	rollback := func(err error) error {
		l.lastSeq--
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return rollback(fmt.Errorf("create event directory: %w", err))
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return rollback(fmt.Errorf("open event log: %w", err))
	}
	if err := json.NewEncoder(file).Encode(event); err != nil {
		_ = file.Close()
		return rollback(fmt.Errorf("append event: %w", err))
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return rollback(fmt.Errorf("sync event log: %w", err))
	}
	if err := file.Close(); err != nil {
		return rollback(fmt.Errorf("close event log: %w", err))
	}
	return nil
}

// ScanPage is one newest-first slice of the log positioned by a physical
// line anchor.
type ScanPage struct {
	Events []Event
	// NextAnchor is the physical line to pass on the following call
	// (strictly older lines are returned); zero means the log is exhausted.
	NextAnchor int
	HasMore    bool
	// AnchorFound is false when anchorLine points at a line that is not a
	// readable event (corrupted, or inside a hole), i.e. the continuation
	// point recorded by the previous cursor has moved.
	AnchorFound bool
	// AnchorBeyondLog is true when anchorLine is past the end of the log,
	// meaning the file was truncated or recreated after the cursor was
	// issued. No page can safely continue from that cursor.
	AnchorBeyondLog bool
	// Gaps are corrupt/duplicate/missing positions inside the lines this
	// page actually traversed.
	Gaps []Gap
}

// ScanBefore returns at most limit readable events on physical lines
// strictly older than anchorLine (anchorLine == 0 starts at the newest
// line), newest first. Lines rejected by keep are skipped without
// counting toward limit and without ending the page, so filtered pages
// never stall or come up prematurely short. Because the anchor is a
// physical append position, events appended while a client pages can
// neither duplicate nor displace already-read events.
func (l *EventLog) ScanBefore(anchorLine, limit int, keep func(Event) bool) (ScanPage, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	positions, _, err := l.loadLocked()
	if err != nil {
		return ScanPage{}, err
	}
	page := ScanPage{Events: []Event{}, Gaps: []Gap{}}
	anchorFound := anchorLine == 0

	index := len(positions) - 1
	// Phase 1: advance to lines strictly older than the anchor.
	if anchorLine > 0 {
		if anchorLine > len(positions) {
			page.AnchorBeyondLog = true
		}
		for ; index >= 0; index-- {
			if positions[index].lineNo < anchorLine {
				break
			}
			if positions[index].lineNo == anchorLine && positions[index].event != nil {
				anchorFound = true
			}
		}
	}

	if page.AnchorBeyondLog {
		// The continuation point predates the current file; do not restart
		// at the head, which would re-return entries the client has read.
		page.Events = []Event{}
		page.Gaps = []Gap{{Line: anchorLine, Reason: "cursor anchor is beyond end of log; log was truncated"}}
		page.HasMore = false
		page.AnchorFound = false
		return page, nil
	}

	var (
		newestLine int
		oldestLine int
	)
	for ; index >= 0; index-- {
		pos := positions[index]
		if newestLine == 0 {
			newestLine = pos.lineNo
		}
		oldestLine = pos.lineNo
		if pos.event == nil {
			page.Gaps = append(page.Gaps, Gap{Line: pos.lineNo, Reason: pos.reason})
			continue
		}
		if pos.event.Seq != pos.lineNo {
			// A healthy append-only log has seq == line number. A
			// mismatch means the file was truncated/rewritten out of
			// band, so a positional walk would silently skip entries.
			page.Gaps = append(page.Gaps, Gap{
				Line:   pos.lineNo,
				Reason: fmt.Sprintf("seq %d does not match log position %d", pos.event.Seq, pos.lineNo),
			})
		}
		if keep == nil || keep(*pos.event) {
			page.Events = append(page.Events, *pos.event)
			if limit > 0 && len(page.Events) >= limit {
				index--
				break
			}
		}
	}
	page.HasMore = index >= 0
	page.AnchorFound = anchorFound
	if page.HasMore {
		page.NextAnchor = oldestLine
	}
	return page, nil
}

// LatestSeq returns the highest sequence number currently on disk (0 for
// an empty log).
func (l *EventLog) LatestSeq() (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.bootstrapLocked(); err != nil {
		return 0, err
	}
	return l.lastSeq, nil
}

// List returns up to limit events in newest-first order. It is a
// gap-agnostic, best-effort convenience; paginated reads should use
// ScanBefore.
func (l *EventLog) List(limit int) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.bootstrapLocked(); err != nil {
		return nil, fmt.Errorf("load event log: %w", err)
	}
	positions, _, err := l.loadLocked()
	if err != nil {
		return nil, err
	}
	items := make([]Event, 0, len(positions))
	for _, pos := range positions {
		if pos.event != nil {
			items = append(items, *pos.event)
		}
	}
	if limit > 0 && len(items) > limit {
		items = items[len(items)-limit:]
	}
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
	return items, nil
}

func (l *EventLog) Count() (int, error) {
	items, err := l.List(0)
	if err != nil {
		return 0, err
	}
	return len(items), nil
}
