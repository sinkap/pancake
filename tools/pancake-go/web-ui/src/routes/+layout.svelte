<script lang="ts">
	import '../app.css';
	import { page } from '$app/state';

	let { children } = $props();

	const navLinks = [
		{ href: '/', label: 'Dashboard' },
		{ href: '/vms', label: 'VMs' },
		{ href: '/attestations', label: 'Attestations' },
		{ href: '/transparency', label: 'Transparency Log' }
	];

	function isActive(href: string) {
		if (href === '/') return page.url.pathname === '/';
		return page.url.pathname.startsWith(href);
	}
</script>

<svelte:head>
	<title>Pancake Fleet Manager</title>
</svelte:head>

<div class="min-h-screen bg-slate-50 text-slate-900">
	<header class="border-b border-slate-200 bg-white">
		<div class="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
			<a href="/" class="text-xl font-semibold tracking-tight">
				🥞 Pancake Fleet
			</a>
			<nav class="flex gap-1 text-sm">
				{#each navLinks as link (link.href)}
					<a
						href={link.href}
						class="rounded-md px-3 py-1.5 font-medium transition-colors {isActive(link.href)
							? 'bg-slate-900 text-white'
							: 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'}"
					>
						{link.label}
					</a>
				{/each}
			</nav>
		</div>
	</header>

	<main class="mx-auto max-w-7xl px-6 py-8">
		{@render children()}
	</main>
</div>
