import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const DESIGN = new URL('../src/design/', import.meta.url);
const components = readFileSync(new URL('components.css', DESIGN), 'utf8');
const tokens = readFileSync(new URL('tokens.css', DESIGN), 'utf8');

// Set by the component that uses the class, as components.css's Strip section
// says: a percentage and, for segmented and ticked strips, a segment count.
const CONSUMER_SET = ['--rl-segments', '--rl-value'];

function used(css: string): Set<string> {
  return new Set(
    Array.from(css.matchAll(/var\((--[\w-]+)/g), (m) => m[1] ?? ''),
  );
}

function defined(css: string): Set<string> {
  return new Set(
    Array.from(css.matchAll(/(?:^|[\s;{])(--[\w-]+)\s*:/g), (m) => m[1] ?? ''),
  );
}

describe('the vendored components.css', () => {
  it('imports nothing', () => {
    expect(components).not.toMatch(/@import/);
  });

  it('loads nothing from Google Fonts', () => {
    expect(components).not.toMatch(/fonts\.googleapis/);
  });

  it('uses only custom properties that tokens.css or components.css define', () => {
    const available = new Set([...defined(tokens), ...defined(components)]);
    const missing = [...used(components)].filter(
      (name) => !available.has(name),
    );
    expect(missing.sort()).toEqual(CONSUMER_SET);
  });
});
