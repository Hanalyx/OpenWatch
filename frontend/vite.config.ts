import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import fs from 'fs';

// Read version from VERSION file
// In development: ../VERSION (project root)
// In Docker build: ./VERSION (copied to frontend workdir)
function getVersion(): string {
  const possiblePaths = [
    path.resolve(__dirname, '../VERSION'),  // Development
    path.resolve(__dirname, './VERSION'),   // Docker build
    path.resolve(process.cwd(), 'VERSION'), // CWD fallback
  ];

  for (const versionPath of possiblePaths) {
    try {
      if (fs.existsSync(versionPath)) {
        return fs.readFileSync(versionPath, 'utf-8').trim();
      }
    } catch {
      // Try next path
    }
  }
  return '0.0.0-dev';
}

export default defineConfig(({ mode }) => {
  // Load env file based on mode
  const env = loadEnv(mode, process.cwd(), '');

  // Get version from VERSION file or env var
  const appVersion = env.VITE_APP_VERSION || getVersion();

  return {
    plugins: [react()],

    // Define environment variables for the app
    define: {
      'import.meta.env.VITE_APP_VERSION': JSON.stringify(appVersion),
      'import.meta.env.VITE_GIT_COMMIT': JSON.stringify(env.VITE_GIT_COMMIT || null),
      'import.meta.env.VITE_BUILD_DATE': JSON.stringify(env.VITE_BUILD_DATE || null),
    },

    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },

    server: {
      host: '0.0.0.0',
      port: 3001,
      proxy: {
        '/api': {
          target: 'http://localhost:8000',
          changeOrigin: true,
          secure: false,
        },
        '/platform-stats': {
          target: 'http://localhost:8002',
          changeOrigin: true,
          secure: false,
        },
        '/framework-stats': {
          target: 'http://localhost:8002',
          changeOrigin: true,
          secure: false,
        },
        '/all-rules': {
          target: 'http://localhost:8002',
          changeOrigin: true,
          secure: false,
        },
      },
    },

    test: {
      exclude: [
        'e2e/**',
        'node_modules/**',
      ],
    },

    build: {
      outDir: 'build',
      sourcemap: true,
      rollupOptions: {
        output: {
          manualChunks: {
            vendor: ['react', 'react-dom'],
            mui: ['@mui/material', '@mui/icons-material'],
            redux: ['@reduxjs/toolkit', 'react-redux', 'redux-persist'],
          },
        },
      },
      target: 'es2015',
      minify: 'esbuild',
    },
  };
});