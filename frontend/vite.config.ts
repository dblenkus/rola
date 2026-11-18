import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const target = process.env.API_PROXY_TARGET || 'http://localhost:8000';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: Object.fromEntries(
      ['/api', '/django-admin', '/media', '/static2'].map((path) => [
        path,
        { target },
      ]),
    ),
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
  },
});
