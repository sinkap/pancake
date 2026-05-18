// SPA mode: a single client-rendered shell (fallback: 'index.html' in
// adapter-static). No SSR, no prerendering — the fleet-server serves
// the built bundle and the SvelteKit router handles all routes client-side.
export const ssr = false;
export const prerender = false;
