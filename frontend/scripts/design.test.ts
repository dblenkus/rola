import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const DESIGN = new URL('../src/design/', import.meta.url);
const components = readFileSync(new URL('components.css', DESIGN), 'utf8');
const tokens = readFileSync(new URL('tokens.css', DESIGN), 'utf8');
const layers = readFileSync(new URL('layers.css', DESIGN), 'utf8');
const app = readFileSync(new URL('app.css', DESIGN), 'utf8');
const logo = readFileSync(
  new URL('../src/shared/ui/Logo.css', import.meta.url),
  'utf8',
);
const main = readFileSync(
  new URL('../src/app/main.tsx', import.meta.url),
  'utf8',
);

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

  it('declares no cascade layers of its own', () => {
    expect(components).not.toMatch(/@layer/);
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

describe('the cascade layers', () => {
  it('put tokens.css and components.css in design-system, above base', () => {
    const statements = Array.from(
      layers.matchAll(/@(?:layer|import)[^;]*;/g),
      (m) => m[0].replace(/\s+/g, ' '),
    );
    expect(statements).toEqual([
      '@layer base, design-system;',
      "@import url('./tokens.css') layer(design-system);",
      "@import url('./components.css') layer(design-system);",
    ]);
  });

  it('come first in main.tsx, which imports no layered file directly', () => {
    const imports = Array.from(
      main.matchAll(/^import '([^']+\.css)';$/gm),
      (m) => m[1],
    );
    expect(imports[0]).toBe('../design/layers.css');
    expect(imports).not.toContain('../design/tokens.css');
    expect(imports).not.toContain('../design/components.css');
  });
});

/** The declarations of the rule whose selector is `selector`, at any indent. */
function rule(css: string, selector: string): string | undefined {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^( *)${escaped} \\{\\n([^}]*)\\n\\1\\}`, 'm').exec(
    css,
  )?.[2];
}

describe('the logo files for the ground', () => {
  it('show by the ink and reversed properties', () => {
    expect(rule(logo, '.ui-logo--ink')).toContain(
      'display: var(--ui-logo-ink);',
    );
    expect(rule(logo, '.ui-logo--reversed')).toContain(
      'display: var(--ui-logo-reversed);',
    );
  });

  it.each([
    [":root,\n[data-theme='light']", 'block', 'none'],
    ["[data-theme='dark']", 'none', 'block'],
  ])('show the files for the ground under %s', (selector, ink, reversed) => {
    const declarations = rule(app, selector);
    expect(declarations).toContain(`--ui-logo-ink: ${ink};`);
    expect(declarations).toContain(`--ui-logo-reversed: ${reversed};`);
  });

  it('show the white file on a dark device when the page names no theme', () => {
    expect(app).toContain(
      [
        '@media (prefers-color-scheme: dark) {',
        '  :root:not([data-theme]) {',
        '    --ui-logo-ink: none;',
        '    --ui-logo-reversed: block;',
        '  }',
        '}',
      ].join('\n'),
    );
  });

  it('declare the pair after the light pair, as tokens.css orders its blocks', () => {
    const light = app.indexOf(":root,\n[data-theme='light'] {");
    const dark = app.indexOf("[data-theme='dark'] {");
    const system = app.indexOf('@media (prefers-color-scheme: dark) {');
    expect(light).toBeGreaterThan(-1);
    expect(dark).toBeGreaterThan(light);
    expect(system).toBeGreaterThan(dark);
  });
});
