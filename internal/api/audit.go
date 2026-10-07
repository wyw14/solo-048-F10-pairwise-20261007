package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"heatpulse/internal/audit"
)

// listAuditEntries serves GET /api/v1/audit-entries with filtering by
// entity, event type, operator, outcome, severity and time window, plus
// stable cursor pagination. See audit.Query.PageN for the paging rules.
func (a *App) listAuditEntries(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := audit.Filter{
		EntityID: query.Get("entity_id"),
		Action:   query.Get("action"),
		Actor:    query.Get("actor"),
		Outcome:  audit.Outcome(query.Get("outcome")),
	}

	switch filter.Outcome {
	case "", audit.OutcomeAccepted, audit.OutcomeRejected, audit.OutcomeCompleted, audit.OutcomeFailed:
	default:
		writeError(w, http.StatusBadRequest, errors.New("outcome must be one of accepted, rejected, completed, failed"))
		return
	}

	if raw := query.Get("severity"); raw != "" {
		severity, ok := audit.ParseSeverity(raw)
		if !ok {
			writeError(w, http.StatusBadRequest, errors.New("severity must be one of info, warning, critical"))
			return
		}
		filter.Severity = severity
	}

	if raw := query.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("since must be an RFC3339 timestamp"))
			return
		}
		filter.Since = t
	}
	if raw := query.Get("until"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("until must be an RFC3339 timestamp"))
			return
		}
		filter.Until = t
	}
	if !filter.Since.IsZero() && !filter.Until.IsZero() && filter.Until.Before(filter.Since) {
		writeError(w, http.StatusBadRequest, errors.New("until must not be before since"))
		return
	}

	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 0 {
			writeError(w, http.StatusBadRequest, errors.New("limit must be a non-negative integer"))
			return
		}
		filter.Limit = limit
	}

	page, err := a.AuditQuery.PageN(filter, query.Get("cursor"))
	if err != nil {
		switch {
		case errors.Is(err, audit.ErrCursor), errors.Is(err, audit.ErrCursorFilter):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, audit.ErrLogTruncated):
			writeError(w, http.StatusConflict, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, page)
}
