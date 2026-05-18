<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { api, pollLoad, formatRelative } from '$lib/api';
	import type { Attestation } from '$lib/types';
	import StatusBadge from '$lib/StatusBadge.svelte';

	type Mode = 'latest' | 'all';
	let mode = $state<Mode>('latest');
	let statusFilter = $state<string>('all'); // all | valid | invalid | error
	let rows = $state<Attestation[]>([]);
	let error = $state<string | null>(null);
	let stop: (() => void) | null = null;

	function reload() {
		stop?.();
		const fetcher = mode === 'latest'
			? () => api.listLatestAttestations()
			: () => api.listAttestations(200);
		stop = pollLoad(
			fetcher,
			(r) => (rows = r.attestations ?? []),
			(e) => (error = String(e))
		);
	}

	$effect(() => {
		// Re-subscribe whenever the mode toggle changes.
		// (statusFilter is applied client-side; no server round-trip.)
		void mode;
		reload();
	});

	onMount(() => reload());
	onDestroy(() => stop?.());

	const filtered = $derived(
		statusFilter === 'all'
			? rows
			: rows.filter((a) => a.verification_status === statusFilter)
	);

	const counts = $derived({
		valid: rows.filter((a) => a.verification_status === 'valid').length,
		invalid: rows.filter((a) => a.verification_status === 'invalid').length,
		error: rows.filter((a) => a.verification_status === 'error').length
	});
</script>

<div class="mb-4 flex items-baseline justify-between gap-4">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Attestations</h1>
		<p class="text-sm text-slate-500">
			{#if mode === 'latest'}
				Latest attestation per VM ({rows.length} VMs).
			{:else}
				Most recent {rows.length} attestations across the fleet (capped at 200).
			{/if}
		</p>
	</div>

	<div class="flex items-center gap-2">
		<div class="inline-flex overflow-hidden rounded-md border border-slate-300 text-sm">
			<button
				class="px-3 py-1 {mode === 'latest' ? 'bg-slate-900 text-white' : 'bg-white hover:bg-slate-100 text-slate-700'}"
				onclick={() => (mode = 'latest')}>Latest per VM</button>
			<button
				class="px-3 py-1 {mode === 'all' ? 'bg-slate-900 text-white' : 'bg-white hover:bg-slate-100 text-slate-700'}"
				onclick={() => (mode = 'all')}>Show full log</button>
		</div>

		<select
			bind:value={statusFilter}
			class="rounded-md border border-slate-300 bg-white px-2 py-1 text-sm">
			<option value="all">All ({rows.length})</option>
			<option value="valid">Valid ({counts.valid})</option>
			<option value="invalid">Invalid ({counts.invalid})</option>
			<option value="error">Error ({counts.error})</option>
		</select>
	</div>
</div>

{#if error}
	<div class="mb-4 rounded-md border border-rose-200 bg-rose-50 px-4 py-2 text-sm text-rose-700">{error}</div>
{/if}

<div class="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
	<table class="min-w-full divide-y divide-slate-200 text-sm">
		<thead class="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
			<tr>
				<th class="px-4 py-2 text-left">VM</th>
				<th class="px-4 py-2 text-left">Status</th>
				<th class="px-4 py-2 text-left">When</th>
				<th class="px-4 py-2 text-left">Mode</th>
				<th class="px-4 py-2 text-left">PCRs</th>
				<th class="px-4 py-2 text-left">EK chain</th>
				<th class="px-4 py-2 text-left">Notes</th>
			</tr>
		</thead>
		<tbody class="divide-y divide-slate-100">
			{#each filtered as a (a.id)}
				<tr class="hover:bg-slate-50">
					<td class="px-4 py-2">
						<a href="/vms/{a.vm_id}" class="font-medium text-slate-900 hover:underline">vm #{a.vm_id}</a>
					</td>
					<td class="px-4 py-2"><StatusBadge status={a.verification_status} /></td>
					<td class="px-4 py-2 text-slate-500">{formatRelative(a.timestamp)}</td>
					<td class="px-4 py-2 text-slate-600">{a.attestation_mode}</td>
					<td class="px-4 py-2 text-slate-600">{Object.keys(a.pcrs ?? {}).length}</td>
					<td class="px-4 py-2 text-slate-600">
						{#if a.ek_chain_verified === true}
							<span class="text-emerald-700">✓ trusted</span>
						{:else if a.ek_chain_verified === false}
							<span class="text-rose-700">✗ failed</span>
						{:else}
							<span class="text-slate-400">—</span>
						{/if}
					</td>
					<td class="px-4 py-2 text-xs text-rose-700">{a.verification_error ?? ''}</td>
				</tr>
			{:else}
				<tr>
					<td colspan="7" class="px-4 py-6 text-center text-slate-400">
						{#if rows.length > 0}
							no rows match the filter
						{:else if mode === 'latest'}
							no VMs have been attested yet — trigger one from a VM's detail page
						{:else}
							no attestations yet
						{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>

<p class="mt-4 text-xs text-slate-400">
	Poll interval (server-side) defaults to 1h. On-demand attestation runs synchronously from the VM detail page.
</p>
