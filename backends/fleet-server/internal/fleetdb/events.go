package fleetdb

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"
)

// FleetEvent mirrors the fleet_events table (transparency log).
type FleetEvent struct {
	ID            int32
	EventType     string
	VMID          *int32 // nullable
	Timestamp     time.Time
	DetailsJSON   string
	EventHash     []byte
	PrevEventHash []byte
}

// InsertEvent appends a new event to the transparency log, computing
// event_hash = SHA256(prev_hash || canonical(event_type, vm_id, details)).
//
// This chaining makes the log tamper-evident: any modification to a past
// event breaks every subsequent hash. External auditors can periodically
// fetch the latest hash and compare.
func (db *DB) InsertEvent(ctx context.Context, eventType string, vmID *int32, detailsJSON string) (int32, error) {
	// Read the most recent event_hash to chain from.
	var prevHash []byte
	const prevQ = `SELECT event_hash FROM fleet_events ORDER BY id DESC LIMIT 1`
	if err := db.QueryRow(ctx, prevQ).Scan(&prevHash); err != nil {
		// If table is empty, prevHash stays nil — that's the genesis event.
		prevHash = nil
	}

	// Canonical-ish event representation. We don't need JCS-level
	// determinism here because we control the serialization; map ordering
	// is stable through encoding/json on a struct.
	canon, err := json.Marshal(struct {
		EventType string  `json:"event_type"`
		VMID      *int32  `json:"vm_id"`
		Details   string  `json:"details"`
		Time      string  `json:"time"` // RFC3339Nano (server NOW())
	}{
		EventType: eventType,
		VMID:      vmID,
		Details:   asJSON(detailsJSON),
		Time:      time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return 0, err
	}

	h := sha256.New()
	h.Write(prevHash)
	h.Write(canon)
	eventHash := h.Sum(nil)

	const insertQ = `
INSERT INTO fleet_events (
    event_type, vm_id, details, event_hash, prev_event_hash
) VALUES ($1, $2, $3::jsonb, $4, $5)
RETURNING id`
	var id int32
	err = db.QueryRow(ctx, insertQ,
		eventType, vmID, asJSON(detailsJSON), eventHash, prevHash,
	).Scan(&id)
	return id, err
}

// ListEvents returns the most recent events (transparency log view).
func (db *DB) ListEvents(ctx context.Context, eventType string, limit int) ([]FleetEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	const q = `
SELECT id, event_type, vm_id, timestamp, details::text,
       event_hash, prev_event_hash
  FROM fleet_events
 WHERE ($1 = '' OR event_type = $1)
 ORDER BY id DESC
 LIMIT $2`
	rows, err := db.Query(ctx, q, eventType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []FleetEvent
	for rows.Next() {
		var e FleetEvent
		if err := rows.Scan(
			&e.ID, &e.EventType, &e.VMID, &e.Timestamp, &e.DetailsJSON,
			&e.EventHash, &e.PrevEventHash,
		); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
