-- Initial pancake fleet schema.
--
-- Tables:
--   vms                 — one row per enrolled VM
--   attestation_log     — append-only TPM attestation results
--   expected_pcrs       — known-good PCR values per generation
--   fleet_events        — transparency log (event chain)

CREATE TABLE vms (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) UNIQUE NOT NULL,
    platform        VARCHAR(50)  NOT NULL,            -- gce, self-hosted, azure, ...
    internal_ip     INET,
    external_ip     INET,
    enrolled_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    cert_serial     VARCHAR(255),
    cert_expires_at TIMESTAMPTZ,
    last_heartbeat  TIMESTAMPTZ,
    last_attestation TIMESTAMPTZ,
    attestation_status VARCHAR(50) NOT NULL DEFAULT 'never',
                    -- 'never', 'valid', 'failed', 'quarantined'
    current_generation INTEGER,
    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vms_platform              ON vms(platform);
CREATE INDEX idx_vms_attestation_status    ON vms(attestation_status);
CREATE INDEX idx_vms_last_attestation      ON vms(last_attestation DESC);

CREATE TABLE attestation_log (
    id                  SERIAL PRIMARY KEY,
    vm_id               INTEGER NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    nonce               BYTEA NOT NULL,
    pcrs                JSONB NOT NULL,        -- {"7": "hex...", "11": "hex...", ...}
    quote               BYTEA NOT NULL,
    signature           BYTEA NOT NULL,
    ak_pub              BYTEA,
    ek_pub              BYTEA,
    verification_status VARCHAR(50) NOT NULL,  -- 'valid', 'invalid', 'error'
    verification_error  TEXT,
    event_log           BYTEA,
    attestation_mode    VARCHAR(50) NOT NULL   -- 'custom', 'gce-shielded'
);

CREATE INDEX idx_attestation_vm_id     ON attestation_log(vm_id);
CREATE INDEX idx_attestation_timestamp ON attestation_log(timestamp DESC);
CREATE INDEX idx_attestation_status    ON attestation_log(verification_status);

CREATE TABLE expected_pcrs (
    generation  INTEGER PRIMARY KEY,
    pcrs        JSONB NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE fleet_events (
    id              SERIAL PRIMARY KEY,
    event_type      VARCHAR(50) NOT NULL,
                    -- 'enrollment', 'attestation_success', 'attestation_failure',
                    -- 'update_pushed', 'quarantine', 'cert_renewed', ...
    vm_id           INTEGER REFERENCES vms(id) ON DELETE SET NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details         JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Transparency log chain. event_hash = SHA256(prev_hash || canonical(event)).
    -- Lets external auditors verify the log is append-only + tamper-evident.
    event_hash      BYTEA,
    prev_event_hash BYTEA
);

CREATE INDEX idx_events_timestamp ON fleet_events(timestamp DESC);
CREATE INDEX idx_events_type      ON fleet_events(event_type);
CREATE INDEX idx_events_vm_id     ON fleet_events(vm_id);
