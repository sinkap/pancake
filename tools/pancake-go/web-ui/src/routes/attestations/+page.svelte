<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { api, pollLoad, formatRelative } from '$lib/api';
	import type { Attestation } from '$lib/types';
	import StatusBadge from '$lib/StatusBadge.svelte';

	let attestations = $state<Attestation[]>([]);
	let error = $state<string | null>(null);
	let stop: (() => void) | null = null;

	onMount(() => {
		stop = pollLoad(
			() => api.listAttestations(200),
			(r) => (attestations = r.attestations ?? []),
			(e) => (error = String(e))
		);
	});
	onDestroy(() => stop?.());
</script>

<h1 class="mb-2 text-2xl font-bold tracking-tight">Attestation log</h1>
<p class="mb-6 text-sm text-slate-500">Most recent {attestations.length} attestations, fleet-wide.</p>

{#if error}
	<div class="mb-4 rounded-md border border-rose-200 bg-rose-50 px-4 py-2 text-sm text-rose-700">{error}</div>
{/if}

<div class="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
	<table class="min-w-full divide-y divide-slate-200 text-sm">
		<thead class="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
			<tr>
				<th class="px-4 py-2 text-left">ID</th>
				<th class="px-4 py-2 text-left">VM</th>
				<th class="px-4 py-2 text-left">Mode</th>
				<th class="px-4 py-2 text-left">Status</th>
				<th class="px-4 py-2 text-left">When</th>
				<th class="px-4 py-2 text-left">PCRs</th>
				<th class="px-4 py-2 text-left">Notes</th>
			</tr>
		</thead>
		<tbody class="divide-y divide-slate-100">
			{#each attestations as a (a.id)}
				<tr class="hover:bg-slate-50">
					<td class="px-4 py-2 font-mono text-xs text-slate-500">{a.id}</td>
					<td class="px-4 py-2"><a href="/vms/{a.vm_id}" class="text-slate-900 hover:underline">vm #{a.vm_id}</a></td>
					<td class="px-4 py-2 text-slate-600">{a.attestation_mode}</td>
					<td class="px-4 py-2"><StatusBadge status={a.verification_status} /></td>
					<td class="px-4 py-2 text-slate-500">{formatRelative(a.timestamp)}</td>
					<td class="px-4 py-2 text-slate-600">{Object.keys(a.pcrs ?? {}).length}</td>
					<td class="px-4 py-2 text-xs text-rose-700">{a.verification_error ?? ''}</td>
				</tr>
			{:else}
				<tr><td colspan="7" class="px-4 py-6 text-center text-slate-400">no attestations yet</td></tr>
			{/each}
		</tbody>
	</table>
</div>
