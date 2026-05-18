// REST API types — mirror fleet-server/internal/fleetapi schemas.

export type AttestationStatus = 'valid' | 'failed' | 'never' | 'quarantined';

export interface VM {
	id: number;
	name: string;
	platform: string;
	internal_ip?: string;
	external_ip?: string;
	enrolled_at: string;
	cert_serial?: string;
	cert_expires_at?: string;
	last_heartbeat?: string;
	last_attestation?: string;
	attestation_status: AttestationStatus;
	current_generation: number;
	metadata?: Record<string, unknown>;
}

export interface VMListResponse {
	vms: VM[];
	total: number;
	offset: number;
}

export interface Attestation {
	id: number;
	vm_id: number;
	timestamp: string;
	nonce_hex: string;
	pcrs: Record<string, string>;
	quote_hex: string;
	signature_hex: string;
	ak_pub_hex?: string;
	ek_pub_hex?: string;
	verification_status: string;
	verification_error?: string;
	event_log_size: number;
	attestation_mode: string;
}

export interface AttestationListResponse {
	attestations: Attestation[];
}

export interface FleetStats {
	total: number;
	healthy: number;
	failed: number;
	never_attested: number;
	quarantined: number;
	stale_heartbeats: number;
	certs_expiring_soon: number;
}

export interface FleetEvent {
	id: number;
	event_type: string;
	vm_id?: number;
	timestamp: string;
	details: Record<string, unknown>;
	event_hash: string;
	prev_event_hash: string;
}

export interface EventListResponse {
	events: FleetEvent[];
}

export interface Generation {
	generation: number;
	pcrs: Record<string, string>;
	description?: string;
	created_at: string;
}

export interface GenerationListResponse {
	generations: Generation[];
}
