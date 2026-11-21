import { existsSync, readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { manifest } from './vite.config.ts';

const read = (path: string): string =>
  readFileSync(new URL(path, import.meta.url), 'utf8');

describe('the web app manifest', () => {
  it('takes its colours from the ink and paper tokens', () => {
    expect(manifest).toMatchObject({
      theme_color: '#111111',
      background_color: '#FFFFFF',
    });
  });

  it('gives the browser chrome the theme colour index.html gives it', () => {
    const meta = /<meta name="theme-color" content="([^"]+)"/.exec(
      read('./index.html'),
    );
    expect(meta?.[1]).toBe(manifest.theme_color);
  });

  it('names only icons that public/ holds', () => {
    const icons = manifest.icons ?? [];
    expect(icons.map((icon) => icon.purpose)).toEqual([
      'any',
      'any',
      'maskable',
    ]);
    for (const { src } of icons) {
      expect(existsSync(new URL(`./public${src}`, import.meta.url))).toBe(true);
    }
  });
});

describe('the appearance before the first paint', () => {
  const html = read('./index.html');
  const script = '<script src="/appearance.js"></script>';

  it('is set by a classic script in the head, before the app module', () => {
    const head = /<head>([\s\S]*)<\/head>/.exec(html)?.[1] ?? '';
    expect(head).toContain(script);
    const entry = html.indexOf('<script type="module"');
    expect(entry).toBeGreaterThan(-1);
    expect(html.indexOf(script)).toBeLessThan(entry);
  });

  it('comes from a script that public/ holds', () => {
    expect(existsSync(new URL('./public/appearance.js', import.meta.url))).toBe(
      true,
    );
  });

  it('lets the browser draw its own controls in either scheme', () => {
    const meta = /<meta name="color-scheme" content="([^"]+)"/.exec(html);
    expect(meta?.[1]).toBe('light dark');
  });
});
