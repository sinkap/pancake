import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	compilerOptions: {
		runes: ({ filename }) => (filename.split(/[/\\]/).includes('node_modules') ? undefined : true)
	},
	kit: {
		// SPA mode: all routes prerendered as one index.html with client-side routing.
		// The fleet-server serves these static files at / and the REST API at /api/v1.
		adapter: adapter({
			fallback: 'index.html',
			pages: 'build',
			assets: 'build',
			precompress: false
		})
	}
};

export default config;
