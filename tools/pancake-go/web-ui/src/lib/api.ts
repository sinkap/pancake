// Thin fetch wrapper around the fleet-server REST API.

import type {
	VM,
	VMListResponse,
	AttestationListResponse,
	FleetStats,
	EventListResponse,
	Generation,
	GenerationListResponse
} from './types';

const BASE = '/api/v1';

async function getJSON<T>(path: string, opts?: RequestInit): Promise<T> {
	const res = await fetch(BASE + path, opts);
	if (!res.ok) {
		const text = await res.text();
		throw new Error(`${res.status} ${res.statusText}: ${text}`);
	}
	return res.json() as Promise<T>;
}

export const api = {
	listVMs(filters?: { platform?: string; status?: string; pageSize?: number }) {
		const q = new URLSearchParams();
		if (filters?.platform) q.set('platform', filters.platform);
		if (filters?.status) q.set('status', filters.status);
		if (filters?.pageSize) q.set('page_size', String(filters.pageSize));
		const qs = q.toString() ? `?${q.toString()}` : '';
		return getJSON<VMListResponse>(`/vms${qs}`);
	},

	getVM(id: number) {
		return getJSON<VM>(`/vms/${id}`);
	},

	listVMAttestations(id: number, limit = 50) {
		return getJSON<AttestationListResponse>(`/vms/${id}/attestations?limit=${limit}`);
	},

	listAttestations(limit = 100) {
		return getJSON<AttestationListResponse>(`/attestations?limit=${limit}`);
	},

	stats() {
		return getJSON<FleetStats>('/stats');
	},

	listEvents(opts?: { type?: string; limit?: number }) {
		const q = new URLSearchParams();
		if (opts?.type) q.set('type', opts.type);
		if (opts?.limit) q.set('limit', String(opts.limit));
		const qs = q.toString() ? `?${q.toString()}` : '';
		return getJSON<EventListResponse>(`/events${qs}`);
	},

	attestVM(id: number) {
		return getJSON<{ status: string; message: string }>(`/vms/${id}/attest`, {
			method: 'POST'
		});
	},

	listGenerations() {
		return getJSON<GenerationListResponse>('/generations');
	},

	putGeneration(gen: number, pcrs: Record<string, string>, description = '') {
		return getJSON<Generation>(`/generations/${gen}`, {
			method: 'PUT',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ pcrs, description })
		});
	}
};

// Auto-refresh helper: re-runs `loader` every `intervalMs` until the returned
// stop() is called. Updates `store` with results (or errors).
export function pollLoad<T>(
	loader: () => Promise<T>,
	onUpdate: (val: T) => void,
	onError: (err: unknown) => void,
	intervalMs = 5000
): () => void {
	let stopped = false;
	const tick = async () => {
		try {
			const v = await loader();
			if (!stopped) onUpdate(v);
		} catch (e) {
			if (!stopped) onError(e);
		} finally {
			if (!stopped) setTimeout(tick, intervalMs);
		}
	};
	tick();
	return () => {
		stopped = true;
	};
}

export function formatRelative(iso?: string): string {
	if (!iso) return 'never';
	const d = new Date(iso);
	const diff = (Date.now() - d.getTime()) / 1000;
	if (diff < 60) return `${Math.floor(diff)}s ago`;
	if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
	if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
	return `${Math.floor(diff / 86400)}d ago`;
}
