<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { api, pollLoad, formatRelative } from '$lib/api';
	import type { FleetEvent } from '$lib/types';

	let events = $state<FleetEvent[]>([]);
	let error = $state<string | null>(null);
	let typeFilter = $state('');
	let stop: (() => void) | null = null;

	function refresh() {
		stop?.();
		stop = pollLoad(
			() => api.listEvents({ type: typeFilter || undefined, limit: 200 }),
			(r) => (events = r.events ?? []),
			(e) => (error = String(e))
		);
	}

	onMount(refresh);
	onDestroy(() => stop?.());

	$effect(() => {
		typeFilter;
		refresh();
	});
</script>

<div class="mb-6 flex items-baseline justify-between">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Transparency log</h1>
		<p class="mt-1 text-sm text-slate-500">
			Append-only fleet event log. Each entry hashes the previous, so any tampering breaks the chain.
		</p>
	</div>
	<label class="flex items-center gap-2 text-sm">
		Filter
		<select bind:value={typeFilter} class="rounded-md border border-slate-300 bg-white px-2 py-1">
			<option value="">all events</option>
			<option value="enrollment">enrollment</option>
			<option value="attestation_success">attestation_success</option>
			<option value="attestation_failure">attestation_failure</option>
		</select>
	</label>
</div>

{#if error}
	<div class="mb-4 rounded-md border border-rose-200 bg-rose-50 px-4 py-2 text-sm text-rose-700">{error}</div>
{/if}

<div class="space-y-3">
	{#each events as ev (ev.id)}
		<article class="rounded-lg border border-slate-200 bg-white p-4 text-sm shadow-sm">
			<div class="flex items-baseline justify-between">
				<div>
					<span class="font-medium text-slate-900">{ev.event_type}</span>
					{#if ev.vm_id}
						<a class="ml-2 text-xs text-slate-500 hover:underline" href="/vms/{ev.vm_id}">vm #{ev.vm_id}</a>
					{/if}
				</div>
				<time class="text-xs text-slate-400">{new Date(ev.timestamp).toLocaleString()} · {formatRelative(ev.timestamp)}</time>
			</div>
			{#if Object.keys(ev.details ?? {}).length > 0}
				<pre class="mt-2 overflow-auto rounded-md bg-slate-50 p-2 text-xs text-slate-700">{JSON.stringify(ev.details, null, 2)}</pre>
			{/if}
			<div class="mt-2 grid grid-cols-[auto_1fr] gap-x-2 text-xs text-slate-400">
				<span>hash</span>
				<code class="break-all font-mono">{ev.event_hash}</code>
				<span>prev</span>
				<code class="break-all font-mono">{ev.prev_event_hash || '(genesis)'}</code>
			</div>
		</article>
	{:else}
		<div class="rounded-lg border border-slate-200 bg-white px-4 py-6 text-center text-sm text-slate-400 shadow-sm">no events</div>
	{/each}
</div>
