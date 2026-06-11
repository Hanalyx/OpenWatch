import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

// Vite config for OpenWatch frontend.
//
// build.outDir = "dist" — the directory the Go binary embeds via
// //go:embed frontend/dist (see docs/frontend_architecture_adr.md
// D-18).
//
// server.proxy — dev workflow runs Vite on :5173 and Go on
// https://localhost:8443; /api/* requests proxy to Go with the dev
// self-signed cert accepted (secure: false). Cookies pass through
// transparently — the browser sees them as same-origin via the proxy.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    emptyOutDir: true,
    target: 'es2022',
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'https://localhost:8443',
        changeOrigin: true,
        secure: false,
        cookieDomainRewrite: 'localhost',
      },
    },
  },
});
