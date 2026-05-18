<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { api, pollLoad, formatRelative } from '$lib/api';
	import type { FleetStats, FleetEvent, VM } from '$lib/types';
	import StatusBadge from '$lib/StatusBadge.svelte';

	let stats = $state<FleetStats | null>(null);
	let events = $state<FleetEvent[]>([]);
	let vms = $state<VM[]>([]);
	let error = $state<string | null>(null);
	let stops: Array<() => void> = [];

	onMount(() => {
		stops.push(
			pollLoad(
				() => api.stats(),
				(s) => (stats = s),
				(e) => (error = String(e))
			)
		);
		stops.push(
			pollLoad(
				() => api.listEvents({ limit: 10 }),
				(r) => (events = r.events ?? []),
				(e) => (error = String(e))
			)
		);
		stops.push(
			pollLoad(
				() => api.listVMs({ pageSize: 100 }),
				(r) => (vms = r.vms ?? []),
				(e) => (error = String(e))
			)
		);
	});

	onDestroy(() => stops.forEach((s) => s()));

	const cards = $derived(
		stats
			? [
					{ label: 'Total VMs', value: stats.total, tone: 'slate' },
					{ label: 'Healthy', value: stats.healthy, tone: 'emerald' },
					{ label: 'Failed', value: stats.failed, tone: 'rose' },
					{ label: 'Never attested', value: stats.never_attested, tone: 'slate' },
					{ label: 'Quarantined', value: stats.quarantined, tone: 'amber' },
					{ label: 'Stale heartbeats', value: stats.stale_heartbeats, tone: 'amber' },
					{ label: 'Certs expiring (7d)', value: stats.certs_expiring_soon, tone: 'amber' }
				]
			: []
	);

	const toneClasses: Record<string, string> = {
		slate: 'text-slate-700',
		emerald: 'text-emerald-700',
		rose: 'text-rose-700',
		amber: 'text-amber-700'
	};
</script>

<h1 class="mb-2 text-2xl font-bold tracking-tight">Fleet Overview</h1>
<p class="mb-6 text-sm text-slate-500">
	Live snapshot of every pancake VM enrolled with this orchestrator.
</p>

{#if error}
	<div class="mb-6 rounded-md border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
		{error}
	</div>
{/if}

<div class="mb-8 grid grid-cols-2 gap-4 md:grid-cols-4 lg:grid-cols-7">
	{#each cards as c (c.label)}
		<div class="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
			<div class="text-xs font-medium uppercase tracking-wide text-slate-500">{c.label}</div>
			<div class="mt-1 text-2xl font-bold {toneClasses[c.tone] ?? 'text-slate-700'}">
				{c.value}
			</div>
		</div>
	{/each}
</div>

<div class="grid gap-8 lg:grid-cols-2">
	<section>
		<div class="mb-3 flex items-baseline justify-between">
			<h2 class="text-lg font-semibold">Active VMs</h2>
			<a class="text-sm text-slate-500 hover:text-slate-900" href="/vms">View all →</a>
		</div>
		<div class="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
			<table class="min-w-full divide-y divide-slate-200 text-sm">
				<thead class="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
					<tr>
						<th class="px-4 py-2 text-left">Name</th>
						<th class="px-4 py-2 text-left">Platform</th>
						<th class="px-4 py-2 text-left">Status</th>
						<th class="px-4 py-2 text-left">Last attest</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-slate-100">
					{#each vms.slice(0, 8) as vm (vm.id)}
						<tr class="hover:bg-slate-50">
							<td class="px-4 py-2">
								<a href="/vms/{vm.id}" class="font-medium text-slate-900 hover:underline">{vm.name}</a>
							</td>
							<td class="px-4 py-2 text-slate-600">{vm.platform}</td>
							<td class="px-4 py-2"><StatusBadge status={vm.attestation_status} /></td>
							<td class="px-4 py-2 text-slate-500">{formatRelative(vm.last_attestation)}</td>
						</tr>
					{:else}
						<tr><td colspan="4" class="px-4 py-6 text-center text-slate-400">no VMs enrolled yet</td></tr>
					{/each}
				</tbody>
			</table>
		</div>
	</section>

	<section>
		<div class="mb-3 flex items-baseline justify-between">
			<h2 class="text-lg font-semibold">Recent events</h2>
			<a class="text-sm text-slate-500 hover:text-slate-900" href="/transparency">View log →</a>
		</div>
		<div class="space-y-2">
			{#each events as ev (ev.id)}
				<div class="rounded-md border border-slate-200 bg-white px-4 py-2 text-sm shadow-sm">
					<div class="flex items-center justify-between">
						<span class="font-medium">
							{ev.event_type}
							{#if ev.vm_id}
								<a class="ml-1 text-slate-500 hover:underline" href="/vms/{ev.vm_id}">
									vm #{ev.vm_id}
								</a>
							{/if}
						</span>
						<time class="text-xs text-slate-400">{formatRelative(ev.timestamp)}</time>
					</div>
					{#if ev.details && Object.keys(ev.details).length > 0}
						<pre class="mt-1 overflow-hidden text-xs text-slate-500">{JSON.stringify(ev.details)}</pre>
					{/if}
				</div>
			{:else}
				<div class="rounded-md border border-slate-200 bg-white px-4 py-6 text-center text-sm text-slate-400">no events yet</div>
			{/each}
		</div>
	</section>
</div>
