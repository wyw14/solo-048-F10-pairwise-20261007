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
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	EntityID string         `json:"entity_id"`
	Message  string         `json:"message"`
	At       time.Time      `json:"at"`
	Fields   map[string]any `json:"fields,omitempty"`
	// Seq is the event's position in the append-only log, assigned from its
	// line number when the log is read. It is never persisted; because the
	// log is append-only, an existing event's Seq never changes and new
	// appends always receive a larger Seq than anything already read.
	Seq uint64 `json:"-"`
}

type EventLog struct {
	path string
	mu   sync.Mutex
}

func NewEventLog(path string) *EventLog {
	return &EventLog{path: path}
}

func (l *EventLog) Append(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return fmt.Errorf("create event directory: %w", err)
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open event log: %w", err)
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(event); err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	return file.Sync()
}

func (l *EventLog) List(limit int) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	file, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Event{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open event log: %w", err)
	}
	defer file.Close()
	items := make([]Event, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode event: %w", err)
		}
		event.Seq = uint64(len(items))
		items = append(items, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan event log: %w", err)
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
