import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    // Standardized webapp port — matches the standard docker-compose.yml
    // (UNM_WEB_PORT) and docker-compose.dev.yml so "the URL" is always :8080.
    port: 8080,
  },
});
