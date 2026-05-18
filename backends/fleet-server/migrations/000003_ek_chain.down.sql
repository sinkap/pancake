ALTER TABLE vms              DROP COLUMN IF EXISTS ek_chain_verified;
ALTER TABLE vms              DROP COLUMN IF EXISTS ek_cert_serial;
ALTER TABLE attestation_log  DROP COLUMN IF EXISTS ek_chain_verified;
ALTER TABLE attestation_log  DROP COLUMN IF EXISTS ek_cert_serial;
