import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// Vitest picks this up in preference to vite.config.ts (which carries the dev
// server proxy — irrelevant for tests). Component tests opt into jsdom via a
// per-file `@vitest-environment jsdom` docblock; pure unit tests stay on node.
export default defineConfig({
  plugins: [react()],
  test: {
    setupFiles: ['./src/test/setup.ts'],
  },
});
