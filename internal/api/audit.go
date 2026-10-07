package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"heatpulse/internal/audit"
)

func (a *App) listAudit(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := audit.Filter{
		EntityID: query.Get("entity_id"),
		Action:   query.Get("action"),
		Actor:    query.Get("actor"),
		Outcome:  audit.Outcome(query.Get("outcome")),
	}
	if value := query.Get("severity"); value != "" {
		severity := audit.Severity(value)
		if !severity.Valid() {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid severity %q", value))
			return
		}
		filter.Severity = severity
	}
	if value := query.Get("since"); value != "" {
		since, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid since timestamp: %w", err))
			return
		}
		filter.Since = since
	}
	if value := query.Get("until"); value != "" {
		until, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid until timestamp: %w", err))
			return
		}
		filter.Until = until
	}
	if value := query.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid limit %q", value))
			return
		}
		filter.Limit = limit
	}
	page, err := a.AuditQuery.Page(filter, query.Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}
