import { readFileSync } from 'node:fs';

import react from '@vitejs/plugin-react';
import { VitePWA, type ManifestOptions } from 'vite-plugin-pwa';
import { defineConfig } from 'vitest/config';

import { parseTokens } from './scripts/tokens.ts';

const target = process.env.API_PROXY_TARGET || 'http://localhost:8000';

const tokens = parseTokens(
  JSON.parse(
    readFileSync(new URL('./src/design/tokens.json', import.meta.url), 'utf8'),
  ),
);

/** A colour token's literal value; the manifest takes no CSS variables. */
function colorToken(name: string): string {
  const value = tokens.colors.find((color) => color.name === name)?.value;
  if (value === undefined || !value.startsWith('#')) {
    throw new Error(`tokens.json: colour '${name}' is not a hex literal`);
  }
  return value;
}

// The browser chrome takes ink, as index.html's theme-color meta does, and
// the launch screen the page's paper ground.
export const manifest: Partial<ManifestOptions> = {
  id: '/',
  name: 'Rola',
  short_name: 'Rola',
  start_url: '/',
  scope: '/',
  display: 'standalone',
  theme_color: colorToken('ink'),
  background_color: colorToken('paper'),
  icons: [
    {
      src: '/icon-192.png',
      sizes: '192x192',
      type: 'image/png',
      purpose: 'any',
    },
    {
      src: '/icon-512.png',
      sizes: '512x512',
      type: 'image/png',
      purpose: 'any',
    },
    {
      src: '/icon-maskable-512.png',
      sizes: '512x512',
      type: 'image/png',
      purpose: 'maskable',
    },
  ],
};

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      strategies: 'injectManifest',
      srcDir: 'src',
      filename: 'sw.ts',
      // src/app/main.tsx registers the worker (src/app/pwa/), in production
      // builds only.
      injectRegister: false,
      // The build adds <link rel="manifest" href="/site.webmanifest"> to
      // index.html.
      manifestFilename: 'site.webmanifest',
      manifest,
      // globPatterns below already precaches the icons.
      includeManifestIcons: false,
      injectManifest: {
        // The app's JS, CSS and HTML, the fonts, the icons and favicons. Not
        // og-image.png (link previews only) nor img/ (other pages' images).
        globPatterns: [
          '**/*.{js,css,html,woff2}',
          '*.{ico,svg}',
          'apple-touch-icon.png',
          'icon-*.png',
        ],
      },
      devOptions: { enabled: false },
    }),
  ],
  server: {
    proxy: Object.fromEntries(
      ['/api', '/django-admin', '/media', '/static2'].map((path) => [
        path,
        { target },
      ]),
    ),
  },
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: 'app',
          environment: 'jsdom',
          setupFiles: ['./src/test/setup.ts'],
          include: ['src/**/*.test.{ts,tsx}'],
        },
      },
      {
        test: {
          name: 'scripts',
          environment: 'node',
          include: ['scripts/**/*.test.ts', 'vite.config.test.ts'],
        },
      },
    ],
  },
});
