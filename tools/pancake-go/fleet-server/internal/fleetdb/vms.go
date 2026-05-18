package fleetdb

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// VM mirrors the vms table.
type VM struct {
	ID                int32
	Name              string
	Platform          string
	InternalIP        string
	ExternalIP        string
	EnrolledAt        time.Time
	CertSerial        string
	CertExpiresAt     *time.Time
	LastHeartbeat     *time.Time
	LastAttestation   *time.Time
	AttestationStatus string
	CurrentGeneration int32
	MetadataJSON      string
	// EKPub is the TPM2B_PUBLIC blob (TPM2-marshalled, not PEM) of the
	// VM's endorsement key. Populated at first Enroll only — TOFU
	// semantics: subsequent enroll calls do NOT overwrite it. The
	// attestation poller compares this against AttestResponse.EkPub.
	EKPub          []byte
	EKPubFirstSeen *time.Time
}

// UpsertVM inserts a new vms row or updates the existing one (by name).
// Returns the row's id. Called on Enroll RPC.
//
// TOFU on ek_pub: the column is set ONCE on first insert and never
// overwritten on subsequent re-enrolls. A VM that comes back with a
// different ekPub at re-enroll has its mismatch surfaced only at the
// next attestation poll (which compares AttestResponse.EkPub to the
// stored value); the registry itself stays welcoming so a benign
// reboot can re-register without trip-wiring the alarm.
func (db *DB) UpsertVM(ctx context.Context, vm VM) (int32, error) {
	const q = `
INSERT INTO vms (
    name, platform, internal_ip, external_ip,
    cert_serial, cert_expires_at, current_generation, metadata,
    ek_pub, ek_pub_first_seen, updated_at
) VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''),
          NULLIF($5, ''), $6, $7, $8::jsonb,
          NULLIF($9, ''::bytea),
          CASE WHEN $9::bytea <> ''::bytea THEN NOW() ELSE NULL END,
          NOW())
ON CONFLICT (name) DO UPDATE SET
    platform           = EXCLUDED.platform,
    internal_ip        = EXCLUDED.internal_ip,
    external_ip        = EXCLUDED.external_ip,
    cert_serial        = EXCLUDED.cert_serial,
    cert_expires_at    = EXCLUDED.cert_expires_at,
    current_generation = EXCLUDED.current_generation,
    metadata           = EXCLUDED.metadata,
    -- TOFU: only set ek_pub on the FIRST insert. Re-enrolls leave the
    -- previously-recorded value untouched. The poller catches mismatch.
    ek_pub             = COALESCE(vms.ek_pub, EXCLUDED.ek_pub),
    ek_pub_first_seen  = COALESCE(vms.ek_pub_first_seen, EXCLUDED.ek_pub_first_seen),
    updated_at         = NOW()
RETURNING id`
	var id int32
	err := db.QueryRow(ctx, q,
		vm.Name, vm.Platform, vm.InternalIP, vm.ExternalIP,
		vm.CertSerial, vm.CertExpiresAt, vm.CurrentGeneration,
		asJSON(vm.MetadataJSON),
		vm.EKPub,
	).Scan(&id)
	return id, err
}

// UpdateHeartbeat sets last_heartbeat = NOW() and optionally current_generation
// for the named VM. Returns rows affected (0 if VM unknown).
func (db *DB) UpdateHeartbeat(ctx context.Context, name string, gen int32) (int64, error) {
	const q = `
UPDATE vms
   SET last_heartbeat     = NOW(),
       current_generation = COALESCE(NULLIF($2, 0), current_generation),
       updated_at         = NOW()
 WHERE name = $1`
	tag, err := db.Exec(ctx, q, name, gen)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ListVMs returns a filtered, paginated slice of VMs.
// platform/status empty strings disable that filter.
func (db *DB) ListVMs(
	ctx context.Context, platform, status string, pageSize, offset int32,
) (vms []VM, total int32, err error) {
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 100
	}
	const countQ = `
SELECT count(*) FROM vms
 WHERE ($1 = '' OR platform = $1)
   AND ($2 = '' OR attestation_status = $2)`
	if err = db.QueryRow(ctx, countQ, platform, status).Scan(&total); err != nil {
		return nil, 0, err
	}

	const q = `
SELECT id, name, platform,
       COALESCE(internal_ip, '') AS internal_ip,
       COALESCE(external_ip, '') AS external_ip,
       enrolled_at, COALESCE(cert_serial, '') AS cert_serial,
       cert_expires_at, last_heartbeat, last_attestation,
       attestation_status, COALESCE(current_generation, 0) AS current_generation,
       metadata::text, ek_pub, ek_pub_first_seen
  FROM vms
 WHERE ($1 = '' OR platform = $1)
   AND ($2 = '' OR attestation_status = $2)
 ORDER BY id
 LIMIT $3 OFFSET $4`
	rows, err := db.Query(ctx, q, platform, status, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var v VM
		if err := rows.Scan(
			&v.ID, &v.Name, &v.Platform,
			&v.InternalIP, &v.ExternalIP,
			&v.EnrolledAt, &v.CertSerial,
			&v.CertExpiresAt, &v.LastHeartbeat, &v.LastAttestation,
			&v.AttestationStatus, &v.CurrentGeneration,
			&v.MetadataJSON, &v.EKPub, &v.EKPubFirstSeen,
		); err != nil {
			return nil, 0, err
		}
		vms = append(vms, v)
	}
	return vms, total, rows.Err()
}

// GetVMByName fetches a VM row by name. Returns pgx.ErrNoRows if missing.
func (db *DB) GetVMByName(ctx context.Context, name string) (*VM, error) {
	return db.getVMWhere(ctx, "name = $1", name)
}

// GetVMByID fetches a VM row by id. Returns pgx.ErrNoRows if missing.
func (db *DB) GetVMByID(ctx context.Context, id int32) (*VM, error) {
	return db.getVMWhere(ctx, "id = $1", id)
}

func (db *DB) getVMWhere(ctx context.Context, where string, arg any) (*VM, error) {
	q := `
SELECT id, name, platform,
       COALESCE(internal_ip, '') AS internal_ip,
       COALESCE(external_ip, '') AS external_ip,
       enrolled_at, COALESCE(cert_serial, '') AS cert_serial,
       cert_expires_at, last_heartbeat, last_attestation,
       attestation_status, COALESCE(current_generation, 0) AS current_generation,
       metadata::text, ek_pub, ek_pub_first_seen
  FROM vms
 WHERE ` + where
	v := &VM{}
	err := db.QueryRow(ctx, q, arg).Scan(
		&v.ID, &v.Name, &v.Platform,
		&v.InternalIP, &v.ExternalIP,
		&v.EnrolledAt, &v.CertSerial,
		&v.CertExpiresAt, &v.LastHeartbeat, &v.LastAttestation,
		&v.AttestationStatus, &v.CurrentGeneration,
		&v.MetadataJSON, &v.EKPub, &v.EKPubFirstSeen,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// FleetStats summarizes the fleet for the dashboard.
type FleetStats struct {
	Total              int32 `json:"total"`
	Healthy            int32 `json:"healthy"`
	Failed             int32 `json:"failed"`
	NeverAttested      int32 `json:"never_attested"`
	Quarantined        int32 `json:"quarantined"`
	StaleHeartbeats    int32 `json:"stale_heartbeats"`     // last_heartbeat < NOW() - 5min
	CertsExpiringSoon  int32 `json:"certs_expiring_soon"`  // cert_expires_at < NOW() + 7d
}

// Stats returns aggregate fleet counters for the dashboard.
func (db *DB) Stats(ctx context.Context) (*FleetStats, error) {
	const q = `
SELECT
  count(*) AS total,
  count(*) FILTER (WHERE attestation_status = 'valid')       AS healthy,
  count(*) FILTER (WHERE attestation_status = 'failed')      AS failed,
  count(*) FILTER (WHERE attestation_status = 'never')       AS never_attested,
  count(*) FILTER (WHERE attestation_status = 'quarantined') AS quarantined,
  count(*) FILTER (WHERE last_heartbeat IS NULL
                      OR last_heartbeat < NOW() - INTERVAL '5 minutes') AS stale_heartbeats,
  count(*) FILTER (WHERE cert_expires_at IS NOT NULL
                     AND cert_expires_at < NOW() + INTERVAL '7 days')   AS certs_expiring_soon
  FROM vms`
	s := &FleetStats{}
	err := db.QueryRow(ctx, q).Scan(
		&s.Total, &s.Healthy, &s.Failed, &s.NeverAttested,
		&s.Quarantined, &s.StaleHeartbeats, &s.CertsExpiringSoon,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}
