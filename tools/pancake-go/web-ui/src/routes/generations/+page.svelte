<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { api, pollLoad, formatRelative } from '$lib/api';
	import type { Generation } from '$lib/types';

	let generations = $state<Generation[]>([]);
	let error = $state<string | null>(null);
	let selected = $state<Generation | null>(null);
	let stop: (() => void) | null = null;

	onMount(() => {
		stop = pollLoad(
			() => api.listGenerations(),
			(r) => {
				generations = r.generations ?? [];
				if (!selected && generations.length > 0) selected = generations[0];
			},
			(e) => (error = String(e))
		);
	});
	onDestroy(() => stop?.());
</script>

<h1 class="mb-2 text-2xl font-bold tracking-tight">Generations</h1>
<p class="mb-6 text-sm text-slate-500">
	Registered PCR policies for each pancake-os generation. The poller compares each
	VM's reported PCRs against the policy matching its current generation; mismatches
	flip the VM to <span class="font-medium text-rose-700">failed</span>.
	Generations without a registered policy are accepted by default (or auto-learned when
	the server runs with <code>-attest-tofu</code>).
</p>

{#if error}
	<div class="mb-4 rounded-md border border-rose-200 bg-rose-50 px-4 py-2 text-sm text-rose-700">{error}</div>
{/if}

<div class="grid gap-6 lg:grid-cols-[280px_1fr]">
	<aside>
		<h2 class="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-500">Registered</h2>
		<ul class="divide-y divide-slate-200 rounded-lg border border-slate-200 bg-white shadow-sm">
			{#each generations as g (g.generation)}
				<li>
					<button
						onclick={() => (selected = g)}
						class="flex w-full items-center justify-between px-4 py-2 text-left text-sm hover:bg-slate-50 {selected?.generation === g.generation ? 'bg-slate-100' : ''}"
					>
						<span class="font-medium text-slate-900">gen {g.generation}</span>
						<span class="text-xs text-slate-500">{Object.keys(g.pcrs).length} PCRs · {formatRelative(g.created_at)}</span>
					</button>
				</li>
			{:else}
				<li class="px-4 py-6 text-center text-sm text-slate-400">no policies registered</li>
			{/each}
		</ul>
	</aside>

	<section>
		{#if selected}
			<div class="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
				<div class="mb-3 flex items-baseline justify-between">
					<h2 class="text-lg font-semibold">Generation {selected.generation}</h2>
					<time class="text-xs text-slate-500">created {formatRelative(selected.created_at)}</time>
				</div>
				{#if selected.description}
					<p class="mb-3 text-sm text-slate-600">{selected.description}</p>
				{/if}
				<table class="w-full text-xs">
					<tbody>
						{#each Object.entries(selected.pcrs).sort((a, b) => Number(a[0]) - Number(b[0])) as [idx, hex] (idx)}
							<tr class="border-t border-slate-100">
								<td class="px-2 py-1 font-mono text-slate-500">PCR[{idx}]</td>
								<td class="px-2 py-1 break-all font-mono text-slate-900">{hex}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{:else}
			<div class="rounded-lg border border-slate-200 bg-white p-6 text-center text-sm text-slate-400 shadow-sm">
				select a generation to view its PCR policy
			</div>
		{/if}

		<div class="mt-6 rounded-md border border-slate-200 bg-slate-50 p-4 text-sm text-slate-600">
			<strong>Registering a policy:</strong>
			<pre class="mt-2 overflow-auto rounded-md bg-white p-2 text-xs">curl -X PUT http://localhost:8080/api/v1/generations/&lt;gen&gt; \
  -H 'Content-Type: application/json' \
  -d '{`{"pcrs": {"7": "<hex>", "11": "<hex>", ...}, "description": "..."}`}'</pre>
		</div>
	</section>
</div>
