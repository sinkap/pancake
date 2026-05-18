<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { page } from '$app/state';
	import { api, pollLoad, formatRelative } from '$lib/api';
	import type { VM, Attestation } from '$lib/types';
	import StatusBadge from '$lib/StatusBadge.svelte';

	const id = $derived(Number(page.params.id));
	let vm = $state<VM | null>(null);
	let attestations = $state<Attestation[]>([]);
	let selected = $state<Attestation | null>(null);
	let error = $state<string | null>(null);
	let busy = $state(false);
	let attestMsg = $state<string | null>(null);
	let stops: Array<() => void> = [];

	function refresh() {
		stops.forEach((s) => s());
		stops = [];
		stops.push(
			pollLoad(
				() => api.getVM(id),
				(v) => (vm = v),
				(e) => (error = String(e))
			)
		);
		stops.push(
			pollLoad(
				() => api.listVMAttestations(id, 50),
				(r) => {
					attestations = r.attestations ?? [];
					if (!selected && attestations.length > 0) selected = attestations[0];
				},
				(e) => (error = String(e))
			)
		);
	}

	onMount(refresh);
	onDestroy(() => stops.forEach((s) => s()));

	$effect(() => {
		id;
		refresh();
	});

	async function attestNow() {
		busy = true;
		attestMsg = null;
		try {
			const r = await api.attestVM(id);
			attestMsg = r.message ?? r.status;
			// Refresh both the VM (status flips to valid/failed) and the
			// attestation list (the new row should appear at the top)
			// without waiting for the next poll tick.
			refresh();
		} catch (e) {
			attestMsg = `error: ${String(e)}`;
		} finally {
			busy = false;
		}
	}
</script>

{#if vm}
	<div class="mb-6 flex items-baseline justify-between">
		<div>
			<a href="/vms" class="text-sm text-slate-500 hover:underline">← all VMs</a>
			<h1 class="mt-1 text-2xl font-bold tracking-tight">{vm.name}</h1>
			<p class="text-sm text-slate-500">id #{vm.id} · {vm.platform}</p>
		</div>
		<button
			onclick={attestNow}
			disabled={busy}
			class="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white shadow-sm hover:bg-slate-800 disabled:opacity-50"
		>
			{busy ? 'attesting…' : 'Attest now'}
		</button>
	</div>

	{#if error}
		<div class="mb-4 rounded-md border border-rose-200 bg-rose-50 px-4 py-2 text-sm text-rose-700">{error}</div>
	{/if}
	{#if attestMsg}
		<div class="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm text-emerald-700">{attestMsg}</div>
	{/if}

	<div class="mb-8 grid gap-4 md:grid-cols-2">
		<div class="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
			<h2 class="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-500">Identity</h2>
			<dl class="grid grid-cols-2 gap-y-1 text-sm">
				<dt class="text-slate-500">Platform</dt><dd class="text-slate-900">{vm.platform}</dd>
				<dt class="text-slate-500">Internal IP</dt><dd class="font-mono text-slate-900">{vm.internal_ip ?? '—'}</dd>
				<dt class="text-slate-500">External IP</dt><dd class="font-mono text-slate-900">{vm.external_ip ?? '—'}</dd>
				<dt class="text-slate-500">Cert serial</dt><dd class="font-mono text-slate-900">{vm.cert_serial ?? '—'}</dd>
				<dt class="text-slate-500">Cert expires</dt><dd class="text-slate-900">{formatRelative(vm.cert_expires_at)}</dd>
				<dt class="text-slate-500">Current generation</dt><dd class="text-slate-900">{vm.current_generation}</dd>
				<dt class="text-slate-500">Enrolled</dt><dd class="text-slate-900">{formatRelative(vm.enrolled_at)}</dd>
				<dt class="text-slate-500">Last heartbeat</dt><dd class="text-slate-900">{formatRelative(vm.last_heartbeat)}</dd>
				<dt class="text-slate-500">Last attestation</dt><dd class="text-slate-900">{formatRelative(vm.last_attestation)}</dd>
			</dl>
		</div>
		<div class="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
			<h2 class="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-500">Current status</h2>
			<div class="text-3xl"><StatusBadge status={vm.attestation_status} /></div>
			{#if vm.metadata && Object.keys(vm.metadata).length > 0}
				<h3 class="mt-4 mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Metadata</h3>
				<pre class="overflow-auto rounded-md bg-slate-50 p-2 text-xs">{JSON.stringify(vm.metadata, null, 2)}</pre>
			{/if}
		</div>
	</div>

	<div class="grid gap-6 lg:grid-cols-[1fr_2fr]">
		<section>
			<h2 class="mb-2 text-lg font-semibold">Attestation history</h2>
			<ul class="divide-y divide-slate-200 rounded-lg border border-slate-200 bg-white text-sm shadow-sm">
				{#each attestations as a (a.id)}
					<li>
						<button
							onclick={() => (selected = a)}
							class="flex w-full items-center justify-between px-4 py-2 text-left hover:bg-slate-50 {selected?.id === a.id ? 'bg-slate-100' : ''}"
						>
							<span><StatusBadge status={a.verification_status} /></span>
							<span class="text-xs text-slate-500">{formatRelative(a.timestamp)}</span>
						</button>
					</li>
				{:else}
					<li class="px-4 py-6 text-center text-slate-400">no attestations yet</li>
				{/each}
			</ul>
		</section>

		<section>
			<h2 class="mb-2 text-lg font-semibold">Attestation detail</h2>
			{#if selected}
				<div class="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
					<dl class="mb-3 grid grid-cols-2 gap-y-1 text-sm">
						<dt class="text-slate-500">ID</dt><dd class="font-mono">{selected.id}</dd>
						<dt class="text-slate-500">Mode</dt><dd>{selected.attestation_mode}</dd>
						<dt class="text-slate-500">Status</dt><dd><StatusBadge status={selected.verification_status} /></dd>
						<dt class="text-slate-500">Timestamp</dt><dd>{new Date(selected.timestamp).toLocaleString()}</dd>
						<dt class="text-slate-500">Event log</dt><dd>{selected.event_log_size} bytes</dd>
						<dt class="text-slate-500">EK cert serial</dt>
						<dd class="font-mono break-all">{selected.ek_cert_serial || '— (no EK cert)'}</dd>
						<dt class="text-slate-500">EK chain</dt>
						<dd>
							{#if selected.ek_chain_verified === true}
								<span class="text-emerald-700">✓ trusted</span>
							{:else if selected.ek_chain_verified === false}
								<span class="text-rose-700">✗ failed</span>
							{:else}
								<span class="text-slate-500">— no trust root configured</span>
							{/if}
						</dd>
					</dl>
					{#if selected.verification_error}
						<div class="mb-3 rounded-md border border-rose-200 bg-rose-50 p-2 text-xs text-rose-700">
							{selected.verification_error}
						</div>
					{/if}

					<h3 class="mt-3 mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">PCR values</h3>
					<table class="mb-3 w-full text-xs">
						<tbody>
							{#each Object.entries(selected.pcrs ?? {}).sort((a, b) => Number(a[0]) - Number(b[0])) as [idx, hex] (idx)}
								<tr class="border-t border-slate-100">
									<td class="px-2 py-1 font-mono text-slate-500">PCR[{idx}]</td>
									<td class="px-2 py-1 font-mono text-slate-900 break-all">{hex}</td>
								</tr>
							{/each}
						</tbody>
					</table>

					<details class="text-xs">
						<summary class="cursor-pointer text-slate-500 hover:text-slate-700">Raw quote / signature / AK / EK (hex)</summary>
						<dl class="mt-2 space-y-2">
							<div>
								<dt class="text-slate-500">Nonce</dt>
								<dd class="break-all font-mono text-slate-800">{selected.nonce_hex}</dd>
							</div>
							<div>
								<dt class="text-slate-500">Quote</dt>
								<dd class="break-all font-mono text-slate-800">{selected.quote_hex}</dd>
							</div>
							<div>
								<dt class="text-slate-500">Signature</dt>
								<dd class="break-all font-mono text-slate-800">{selected.signature_hex}</dd>
							</div>
							{#if selected.ak_pub_hex}
								<div>
									<dt class="text-slate-500">AK pub</dt>
									<dd class="break-all font-mono text-slate-800">{selected.ak_pub_hex}</dd>
								</div>
							{/if}
							{#if selected.ek_pub_hex}
								<div>
									<dt class="text-slate-500">EK pub</dt>
									<dd class="break-all font-mono text-slate-800">{selected.ek_pub_hex}</dd>
								</div>
							{/if}
						</dl>
					</details>
				</div>
			{:else}
				<div class="rounded-lg border border-slate-200 bg-white p-6 text-center text-sm text-slate-400 shadow-sm">
					select an attestation to view detail
				</div>
			{/if}
		</section>
	</div>
{:else if error}
	<div class="rounded-md border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>
{:else}
	<p class="text-slate-500">loading…</p>
{/if}
