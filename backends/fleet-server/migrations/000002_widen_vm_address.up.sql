-- Switch internal_ip / external_ip from INET to TEXT.
--
-- VMs in real deployments need to be addressable by hostname, not just by
-- IP literal: e.g. host.docker.internal for QEMU dev, or DNS names like
-- pancake-001.internal.example.com for GCE managed instance groups
-- behind internal DNS. INET only accepts IP literals, so it forced
-- workarounds. TEXT subsumes both.

ALTER TABLE vms ALTER COLUMN internal_ip TYPE TEXT USING host(internal_ip);
ALTER TABLE vms ALTER COLUMN external_ip TYPE TEXT USING host(external_ip);
