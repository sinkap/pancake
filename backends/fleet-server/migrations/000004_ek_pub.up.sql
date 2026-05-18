-- ek_pub_tofu: store the VM's EK public area at first enrollment so
-- subsequent attestations can be bytes-equality-verified against it
-- (TOFU model). Pancake's GCE design rationale: Google's vTPM doesn't
-- ship an X.509 EK cert, only ekPub via getShieldedInstanceIdentity.
-- We trust the API once at enrollment and lock the VM to THAT ekPub.
ALTER TABLE vms
  ADD COLUMN ek_pub BYTEA;

-- Capture when the TOFU happened so we can audit later (separate from
-- enrolled_at because we may re-enroll without overwriting ek_pub).
ALTER TABLE vms
  ADD COLUMN ek_pub_first_seen TIMESTAMPTZ;
