-- Revert internal_ip / external_ip to INET (any non-IP rows will fail).
ALTER TABLE vms ALTER COLUMN internal_ip TYPE INET USING internal_ip::inet;
ALTER TABLE vms ALTER COLUMN external_ip TYPE INET USING external_ip::inet;
