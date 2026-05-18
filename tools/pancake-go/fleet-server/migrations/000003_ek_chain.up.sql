-- Capture the result of EK cert chain verification on each attestation.
-- ek_cert_serial: leaf cert serial (hex upper), or NULL if no cert.
-- ek_chain_verified: TRUE when verified against EKTrustRoots,
--                    FALSE on fail, NULL when no chain was presented.

ALTER TABLE attestation_log
  ADD COLUMN ek_cert_serial    TEXT,
  ADD COLUMN ek_chain_verified BOOLEAN;

-- Materialise the latest EK cert serial onto the vms row so the UI
-- can show "EK trusted ✓ <serial>" without joining every page load.
ALTER TABLE vms
  ADD COLUMN ek_cert_serial    TEXT,
  ADD COLUMN ek_chain_verified BOOLEAN;
