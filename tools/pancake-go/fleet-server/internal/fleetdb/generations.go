package fleetdb

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ExpectedPCRs is the known-good set of PCR values for one generation
// of pancake-os. The poller compares an attestation's PCRs against
// the row matching the VM's current_generation; mismatches flip
// verification_status to "invalid".
type ExpectedPCRs struct {
	Generation  int32
	PCRs        map[string]string // PCR index → hex digest
	Description string
	CreatedAt   time.Time
}

// UpsertExpectedPCRs registers (or replaces) the policy for a generation.
// Idempotent.
func (db *DB) UpsertExpectedPCRs(ctx context.Context, gen int32, pcrs map[string]string, desc string) error {
	b, err := json.Marshal(pcrs)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO expected_pcrs (generation, pcrs, description, created_at)
VALUES ($1, $2::jsonb, NULLIF($3, ''), NOW())
ON CONFLICT (generation) DO UPDATE
   SET pcrs        = EXCLUDED.pcrs,
       description = EXCLUDED.description`
	_, err = db.Exec(ctx, q, gen, string(b), desc)
	return err
}

// GetExpectedPCRs returns the registered PCR policy for a generation,
// or pgx.ErrNoRows if no policy exists for that generation.
func (db *DB) GetExpectedPCRs(ctx context.Context, gen int32) (*ExpectedPCRs, error) {
	const q = `
SELECT generation, pcrs::text, COALESCE(description, ''), created_at
  FROM expected_pcrs
 WHERE generation = $1`
	var (
		e       ExpectedPCRs
		pcrsTxt string
	)
	err := db.QueryRow(ctx, q, gen).Scan(&e.Generation, &pcrsTxt, &e.Description, &e.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(pcrsTxt), &e.PCRs); err != nil {
		return nil, err
	}
	return &e, nil
}

// ListExpectedPCRs returns all registered PCR policies (newest first).
func (db *DB) ListExpectedPCRs(ctx context.Context) ([]ExpectedPCRs, error) {
	const q = `
SELECT generation, pcrs::text, COALESCE(description, ''), created_at
  FROM expected_pcrs
 ORDER BY generation DESC`
	rows, err := db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExpectedPCRs
	for rows.Next() {
		var e ExpectedPCRs
		var pcrsTxt string
		if err := rows.Scan(&e.Generation, &pcrsTxt, &e.Description, &e.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(pcrsTxt), &e.PCRs); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
