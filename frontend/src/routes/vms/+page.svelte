<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { api, pollLoad, formatRelative } from '$lib/api';
	import type { VM, AttestationStatus } from '$lib/types';
	import StatusBadge from '$lib/StatusBadge.svelte';

	let vms = $state<VM[]>([]);
	let total = $state(0);
	let error = $state<string | null>(null);
	let platform = $state('');
	let status = $state<AttestationStatus | ''>('');
	let stop: (() => void) | null = null;

	function refresh() {
		stop?.();
		stop = pollLoad(
			() => api.listVMs({ platform: platform || undefined, status: status || undefined, pageSize: 200 }),
			(r) => {
				vms = r.vms ?? [];
				total = r.total;
			},
			(e) => (error = String(e))
		);
	}

	onMount(refresh);
	onDestroy(() => stop?.());

	$effect(() => {
		// Re-poll when filter values change
		platform; status;
		refresh();
	});
</script>

<div class="mb-6 flex items-baseline justify-between">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">VMs</h1>
		<p class="mt-1 text-sm text-slate-500">{total} total · filtered to {vms.length}</p>
	</div>
	<div class="flex gap-3 text-sm">
		<label class="flex items-center gap-2">
			Platform
			<select bind:value={platform} class="rounded-md border border-slate-300 bg-white px-2 py-1">
				<option value="">all</option>
				<option value="self-hosted">self-hosted</option>
				<option value="gce">gce</option>
				<option value="azure">azure</option>
			</select>
		</label>
		<label class="flex items-center gap-2">
			Status
			<select bind:value={status} class="rounded-md border border-slate-300 bg-white px-2 py-1">
				<option value="">all</option>
				<option value="valid">valid</option>
				<option value="failed">failed</option>
				<option value="never">never</option>
				<option value="quarantined">quarantined</option>
			</select>
		</label>
	</div>
</div>

{#if error}
	<div class="mb-4 rounded-md border border-rose-200 bg-rose-50 px-4 py-2 text-sm text-rose-700">
		{error}
	</div>
{/if}

<div class="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
	<table class="min-w-full divide-y divide-slate-200 text-sm">
		<thead class="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
			<tr>
				<th class="px-4 py-2 text-left">ID</th>
				<th class="px-4 py-2 text-left">Name</th>
				<th class="px-4 py-2 text-left">Platform</th>
				<th class="px-4 py-2 text-left">Internal IP</th>
				<th class="px-4 py-2 text-left">Status</th>
				<th class="px-4 py-2 text-left">Gen</th>
				<th class="px-4 py-2 text-left">Last attest</th>
				<th class="px-4 py-2 text-left">Last heartbeat</th>
				<th class="px-4 py-2 text-left">Enrolled</th>
			</tr>
		</thead>
		<tbody class="divide-y divide-slate-100">
			{#each vms as vm (vm.id)}
				<tr class="hover:bg-slate-50">
					<td class="px-4 py-2 font-mono text-xs text-slate-500">{vm.id}</td>
					<td class="px-4 py-2">
						<a href="/vms/{vm.id}" class="font-medium text-slate-900 hover:underline">{vm.name}</a>
					</td>
					<td class="px-4 py-2 text-slate-600">{vm.platform}</td>
					<td class="px-4 py-2 font-mono text-xs text-slate-500">{vm.internal_ip ?? '—'}</td>
					<td class="px-4 py-2"><StatusBadge status={vm.attestation_status} /></td>
					<td class="px-4 py-2 text-slate-600">{vm.current_generation}</td>
					<td class="px-4 py-2 text-slate-500">{formatRelative(vm.last_attestation)}</td>
					<td class="px-4 py-2 text-slate-500">{formatRelative(vm.last_heartbeat)}</td>
					<td class="px-4 py-2 text-slate-500">{formatRelative(vm.enrolled_at)}</td>
				</tr>
			{:else}
				<tr><td colspan="9" class="px-4 py-6 text-center text-slate-400">no VMs match the current filters</td></tr>
			{/each}
		</tbody>
	</table>
</div>
