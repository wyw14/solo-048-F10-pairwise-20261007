package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"heatpulse/internal/audit"
)

type auditEnvelope struct {
	Data struct {
		Entries    []audit.Entry `json:"entries"`
		NextCursor string        `json:"next_cursor"`
		HasMore    bool          `json:"has_more"`
		HasGaps    bool          `json:"has_gaps"`
	} `json:"data"`
	Error string `json:"error"`
}

func setupAuditApp(t *testing.T) (*App, http.Handler) {
	t.Helper()
	app, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return app, app.Handler()
}

func TestAuditEntriesEndpointFiltersAndPages(t *testing.T) {
	app, handler := setupAuditApp(t)
	base := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	entries := []audit.Entry{
		{Action: "pump.stage", EntityID: "north", Actor: "alice", Outcome: audit.OutcomeAccepted, At: base},
		{Action: "pump.stage", EntityID: "east", Actor: "bob", Outcome: audit.OutcomeRejected, At: base.Add(time.Hour)},
		{Action: "valve.open", EntityID: "north", Actor: "alice", Outcome: audit.OutcomeFailed, At: base.Add(2 * time.Hour)},
	}
	for _, entry := range entries {
		if _, err := app.Audit.Record(entry); err != nil {
			t.Fatal(err)
		}
	}

	get := func(target string) (auditEnvelope, int) {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var envelope auditEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode: %v body=%s", err, rec.Body.String())
		}
		return envelope, rec.Code
	}

	envelope, status := get("/api/v1/audit-entries?actor=alice&severity=critical")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if len(envelope.Data.Entries) != 1 || envelope.Data.Entries[0].Action != "valve.open" {
		t.Fatalf("filter result = %+v", envelope.Data.Entries)
	}

	// Time window.
	envelope, _ = get("/api/v1/audit-entries?since=" + base.Add(30*time.Minute).Format(time.RFC3339))
	if len(envelope.Data.Entries) != 2 {
		t.Fatalf("since filter = %d entries", len(envelope.Data.Entries))
	}

	// Pagination: 3 entries at size 2 -> first page has more.
	envelope, _ = get("/api/v1/audit-entries?limit=2")
	if len(envelope.Data.Entries) != 2 || !envelope.Data.HasMore || envelope.Data.NextCursor == "" {
		t.Fatalf("first page = %+v", envelope.Data)
	}
	next, status := get("/api/v1/audit-entries?limit=2&cursor=" + envelope.Data.NextCursor)
	if status != http.StatusOK {
		t.Fatalf("cursor status = %d", status)
	}
	if len(next.Data.Entries) != 1 || next.Data.HasMore || next.Data.NextCursor != "" {
		t.Fatalf("second page = %+v", next.Data)
	}
}

func TestAuditEntriesEndpointValidation(t *testing.T) {
	_, handler := setupAuditApp(t)
	cases := map[string]int{
		"/api/v1/audit-entries?severity=bogus":                                        http.StatusBadRequest,
		"/api/v1/audit-entries?outcome=maybe":                                         http.StatusBadRequest,
		"/api/v1/audit-entries?since=not-a-time":                                      http.StatusBadRequest,
		"/api/v1/audit-entries?limit=-3":                                              http.StatusBadRequest,
		"/api/v1/audit-entries?cursor=garbage":                                        http.StatusBadRequest,
		"/api/v1/audit-entries?until=2020-01-01T00:00:00Z&since=2026-01-01T00:00:00Z": http.StatusBadRequest,
	}
	for target, want := range cases {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s status = %d, want %d", target, rec.Code, want)
		}
	}
}
