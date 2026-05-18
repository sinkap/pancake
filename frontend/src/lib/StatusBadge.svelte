<script lang="ts">
	import type { AttestationStatus } from './types';

	let { status }: { status: AttestationStatus | string } = $props();

	const styles: Record<string, string> = {
		valid: 'bg-emerald-100 text-emerald-800 ring-emerald-600/20',
		failed: 'bg-rose-100 text-rose-800 ring-rose-600/20',
		never: 'bg-slate-100 text-slate-700 ring-slate-500/20',
		quarantined: 'bg-amber-100 text-amber-800 ring-amber-600/20',
		error: 'bg-rose-100 text-rose-800 ring-rose-600/20',
		invalid: 'bg-rose-100 text-rose-800 ring-rose-600/20'
	};

	const labels: Record<string, string> = {
		valid: '✓ valid',
		failed: '✗ failed',
		never: '— never',
		quarantined: '⚠ quarantined',
		error: '✗ error',
		invalid: '✗ invalid'
	};

	const cls = $derived(styles[status] ?? 'bg-slate-100 text-slate-700 ring-slate-500/20');
	const label = $derived(labels[status] ?? status);
</script>

<span
	class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset {cls}"
>
	{label}
</span>
