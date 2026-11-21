import { readFileSync } from 'node:fs';

import react from '@vitejs/plugin-react';
import { VitePWA, type ManifestOptions } from 'vite-plugin-pwa';
import { defineConfig } from 'vitest/config';

import { colorLiteral, parseTokens } from './scripts/tokens.ts';

const target = process.env.API_PROXY_TARGET || 'http://localhost:8000';

const tokens = parseTokens(
  JSON.parse(
    readFileSync(new URL('./src/design/tokens.json', import.meta.url), 'utf8'),
  ),
);

// The browser chrome takes ink, as index.html's theme-color meta does, and
// the launch screen the page's paper ground. A manifest has one value per
// member and cannot follow the theme, so it takes the light theme's, the
// design system's first.
export const manifest: Partial<ManifestOptions> = {
  id: '/',
  name: 'Rola',
  short_name: 'Rola',
  start_url: '/',
  scope: '/',
  display: 'standalone',
  theme_color: colorLiteral(tokens, 'ink', 'light'),
  background_color: colorLiteral(tokens, 'paper', 'light'),
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
        // The app's JS, CSS and HTML, the fonts, the icons and favicons; the
        // plugin adds site.webmanifest. Not robots.txt, which only crawlers
        // read.
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
