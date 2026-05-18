import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	server: {
		// During dev, proxy /api/v1/* and /healthz to the fleet-server so
		// the UI can be developed without configuring CORS.
		proxy: {
			'/api/v1': 'http://localhost:8080',
			'/healthz': 'http://localhost:8080',
			'/readyz': 'http://localhost:8080'
		}
	}
});
