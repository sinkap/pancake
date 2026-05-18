package fleetdb

import (
	"context"
	"time"
)

// Attestation mirrors the attestation_log table.
type Attestation struct {
	ID                 int32
	VMID               int32
	Timestamp          time.Time
	Nonce              []byte
	PCRs               string // JSONB as JSON text
	Quote              []byte
	Signature          []byte
	AKPub              []byte
	EKPub              []byte
	VerificationStatus string
	VerificationError  string
	EventLog           []byte
	AttestationMode    string // "custom", "gce-shielded"

	// EK chain verification result (migration 000003).
	EKCertSerial    string // leaf serial (hex upper), "" when no EK cert
	EKChainVerified *bool  // nil = no chain presented; T/F = verify result
}

// InsertAttestation appends an attestation record. Also updates the
// vms row's last_attestation and attestation_status atomically.
func (db *DB) InsertAttestation(ctx context.Context, a Attestation) (int32, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	const insertQ = `
INSERT INTO attestation_log (
    vm_id, timestamp, nonce, pcrs, quote, signature,
    ak_pub, ek_pub, verification_status, verification_error,
    event_log, attestation_mode, ek_cert_serial, ek_chain_verified
) VALUES ($1, NOW(), $2, $3::jsonb, $4, $5, $6, $7, $8, NULLIF($9, ''),
          $10, $11, NULLIF($12, ''), $13)
RETURNING id`
	var id int32
	if err := tx.QueryRow(ctx, insertQ,
		a.VMID, a.Nonce, asJSON(a.PCRs), a.Quote, a.Signature,
		a.AKPub, a.EKPub, a.VerificationStatus, a.VerificationError,
		a.EventLog, a.AttestationMode, a.EKCertSerial, a.EKChainVerified,
	).Scan(&id); err != nil {
		return 0, err
	}

	// Update the vms row's denormalized status fields
	status := "failed"
	if a.VerificationStatus == "valid" {
		status = "valid"
	}
	const updateQ = `
UPDATE vms
   SET last_attestation    = NOW(),
       attestation_status  = $2,
       ek_cert_serial      = NULLIF($3, ''),
       ek_chain_verified   = $4,
       updated_at          = NOW()
 WHERE id = $1`
	if _, err := tx.Exec(ctx, updateQ, a.VMID, status, a.EKCertSerial, a.EKChainVerified); err != nil {
		return 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return id, nil
}

// ListAttestations returns attestations for a single VM (most recent first).
// If vmID == 0, returns across the whole fleet.
func (db *DB) ListAttestations(ctx context.Context, vmID int32, limit int) ([]Attestation, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	const qByVM = `
SELECT id, vm_id, timestamp, nonce, pcrs::text, quote, signature,
       ak_pub, ek_pub, verification_status,
       COALESCE(verification_error, '') AS verification_error,
       event_log, attestation_mode,
       COALESCE(ek_cert_serial, '') AS ek_cert_serial,
       ek_chain_verified
  FROM attestation_log
 WHERE vm_id = $1
 ORDER BY timestamp DESC
 LIMIT $2`
	const qAll = `
SELECT id, vm_id, timestamp, nonce, pcrs::text, quote, signature,
       ak_pub, ek_pub, verification_status,
       COALESCE(verification_error, '') AS verification_error,
       event_log, attestation_mode,
       COALESCE(ek_cert_serial, '') AS ek_cert_serial,
       ek_chain_verified
  FROM attestation_log
 ORDER BY timestamp DESC
 LIMIT $1`

	var rowsErr error
	var attestations []Attestation

	var scan func() error
	if vmID == 0 {
		rows, err := db.Query(ctx, qAll, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		scan = func() error {
			for rows.Next() {
				var a Attestation
				if err := rows.Scan(
					&a.ID, &a.VMID, &a.Timestamp, &a.Nonce, &a.PCRs,
					&a.Quote, &a.Signature, &a.AKPub, &a.EKPub,
					&a.VerificationStatus, &a.VerificationError,
					&a.EventLog, &a.AttestationMode,
					&a.EKCertSerial, &a.EKChainVerified,
				); err != nil {
					return err
				}
				attestations = append(attestations, a)
			}
			return rows.Err()
		}
	} else {
		rows, err := db.Query(ctx, qByVM, vmID, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		scan = func() error {
			for rows.Next() {
				var a Attestation
				if err := rows.Scan(
					&a.ID, &a.VMID, &a.Timestamp, &a.Nonce, &a.PCRs,
					&a.Quote, &a.Signature, &a.AKPub, &a.EKPub,
					&a.VerificationStatus, &a.VerificationError,
					&a.EventLog, &a.AttestationMode,
					&a.EKCertSerial, &a.EKChainVerified,
				); err != nil {
					return err
				}
				attestations = append(attestations, a)
			}
			return rows.Err()
		}
	}

	rowsErr = scan()
	if rowsErr != nil {
		return nil, rowsErr
	}
	return attestations, nil
}
