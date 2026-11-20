import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { TOKENS_CSS, buildTokensCss } from './build-tokens.ts';
import { parseTokens, renderTokensCss } from './tokens.ts';

const FRONTEND = fileURLToPath(new URL('..', import.meta.url));

const COLORS = [
  { name: 'ink', value: '#111111', usage: 'Text.' },
  { name: 'paper', value: '#FFFFFF' },
  { name: 'text', value: '{ink}' },
  { name: 'focus', value: '{text}' },
];

function fixture(): Record<string, unknown> {
  return {
    name: 'Fixture',
    version: 1,
    color: { themes: [{ id: 'light', name: 'Light' }], tokens: COLORS },
    type: {
      fonts: [],
      families: { sans: 'Inter, sans-serif', mono: '"DM Mono", monospace' },
      groups: [
        {
          name: 'Headings',
          family: 'sans',
          styles: [
            {
              name: 'h2',
              fontSize: '24px',
              lineHeight: '32px',
              fontWeight: 600,
              letterSpacing: '-0.015em',
              sample: 'Sample',
              usage: 'Panel titles.',
            },
            {
              name: 'h3',
              fontSize: '18px',
              lineHeight: '24px',
              fontWeight: 600,
            },
          ],
        },
        {
          name: 'Data',
          family: 'mono',
          styles: [
            {
              name: 'photo-id',
              fontSize: '14px',
              lineHeight: '20px',
              fontWeight: 400,
            },
          ],
        },
      ],
    },
    spacing: { tokens: [{ name: 'space-4', value: '16px', usage: 'Gaps.' }] },
    radius: { tokens: [{ name: 'radius-control', value: '2px' }] },
    stroke: {
      note: 'Line weights.',
      tokens: [{ name: 'stroke-strip', value: '3px' }],
    },
    film: { tokens: [{ name: 'perf-pitch', value: '16px' }] },
  };
}

function render(raw: unknown): string {
  return renderTokensCss(parseTokens(raw));
}

function rootBlock(css: string): string {
  return /:root \{\n([\s\S]*?)\n\}/.exec(css)?.[1] ?? '';
}

function classBlock(css: string, name: string): string | undefined {
  return new RegExp(`^\\.${name} \\{\\n([\\s\\S]*?)\\n\\}`, 'm').exec(css)?.[1];
}

function withColors(colors: unknown[]): Record<string, unknown> {
  const raw = fixture();
  raw.color = { themes: [{ id: 'light', name: 'Light' }], tokens: colors };
  return raw;
}

describe('renderTokensCss', () => {
  const css = render(fixture());
  const root = rootBlock(css);

  it('starts with the generated-file header', () => {
    expect(css.split('\n')[0]).toBe(
      '/* Generated from tokens.json by scripts/build-tokens.ts. Do not edit; run `npm run tokens`. */',
    );
  });

  it('declares the light colour scheme on :root', () => {
    expect(root).toContain('  color-scheme: light;');
  });

  it('renders literal colours as they are', () => {
    expect(root).toContain('  --ink: #111111;');
    expect(root).toContain('  --paper: #FFFFFF;');
  });

  it('renders colour aliases, including aliases of aliases, as var()', () => {
    expect(root).toContain('  --text: var(--ink);');
    expect(root).toContain('  --focus: var(--text);');
  });

  it('renders every {"tokens": [...]} section', () => {
    expect(root).toContain('  --space-4: 16px;');
    expect(root).toContain('  --radius-control: 2px;');
    expect(root).toContain('  --stroke-strip: 3px;');
    expect(root).toContain('  --perf-pitch: 16px;');
  });

  it('renders the font stacks', () => {
    expect(root).toContain('  --font-sans: Inter, sans-serif;');
    expect(root).toContain('  --font-mono: "DM Mono", monospace;');
  });

  it('renders a type style as a class with its tracking', () => {
    expect(classBlock(css, 'h2')).toBe(
      [
        '  font-family: var(--font-sans);',
        '  font-size: 24px;',
        '  line-height: 32px;',
        '  font-weight: 600;',
        '  letter-spacing: -0.015em;',
      ].join('\n'),
    );
  });

  it('leaves out letter-spacing when the style has none', () => {
    expect(classBlock(css, 'h3')).toBe(
      [
        '  font-family: var(--font-sans);',
        '  font-size: 18px;',
        '  line-height: 24px;',
        '  font-weight: 600;',
      ].join('\n'),
    );
  });

  it("uses the style's group family", () => {
    expect(classBlock(css, 'photo-id')).toContain(
      'font-family: var(--font-mono);',
    );
  });

  it('sets no colour in a type class', () => {
    const classes = css.slice(css.indexOf('.h2 {'));
    expect(classes).not.toMatch(/(^|\s)color:/);
  });
});

describe('parseTokens failures', () => {
  it('rejects an alias of an unknown colour', () => {
    expect(() =>
      parseTokens(
        withColors([...COLORS, { name: 'line', value: '{grey-200}' }]),
      ),
    ).toThrow("colour 'line' is an alias of unknown colour 'grey-200'");
  });

  it('rejects a colour that is neither hex nor an alias', () => {
    expect(() =>
      parseTokens(
        withColors([...COLORS, { name: 'line', value: 'rgb(0 0 0)' }]),
      ),
    ).toThrow(
      "colour 'line' value 'rgb(0 0 0)' is neither a hex colour nor an alias",
    );
  });

  it('rejects a themed colour value', () => {
    expect(() =>
      parseTokens(
        withColors([
          ...COLORS,
          { name: 'line', value: { light: '#DDDDDD', dark: '#333333' } },
        ]),
      ),
    ).toThrow("token 'line' value must be a non-empty string");
  });

  it('rejects an alias cycle', () => {
    expect(() =>
      parseTokens(
        withColors([
          { name: 'a', value: '{b}' },
          { name: 'b', value: '{a}' },
        ]),
      ),
    ).toThrow("colour 'a' has an alias cycle: a -> b -> a");
  });

  it('rejects a second theme', () => {
    const raw = fixture();
    raw.color = {
      themes: [
        { id: 'light', name: 'Light' },
        { id: 'dark', name: 'Dark' },
      ],
      tokens: COLORS,
    };
    expect(() => parseTokens(raw)).toThrow(
      'color.themes must be exactly light, got light, dark',
    );
  });

  it('rejects a duplicate colour', () => {
    expect(() =>
      parseTokens(withColors([...COLORS, { name: 'ink', value: '#000000' }])),
    ).toThrow("duplicate custom property 'ink'");
  });

  it('rejects a token that repeats a name from another section', () => {
    const raw = fixture();
    raw.film = { tokens: [{ name: 'space-4', value: '16px' }] };
    expect(() => parseTokens(raw)).toThrow(
      "duplicate custom property 'space-4'",
    );
  });

  it('rejects a duplicate type style', () => {
    const raw = fixture();
    raw.type = {
      fonts: [],
      families: { sans: 'Inter' },
      groups: [
        {
          name: 'A',
          family: 'sans',
          styles: [
            {
              name: 'body',
              fontSize: '15px',
              lineHeight: '22px',
              fontWeight: 400,
            },
            {
              name: 'body',
              fontSize: '14px',
              lineHeight: '20px',
              fontWeight: 400,
            },
          ],
        },
      ],
    };
    expect(() => parseTokens(raw)).toThrow("duplicate type style 'body'");
  });

  it('rejects a type group with an unknown family', () => {
    const raw = fixture();
    raw.type = {
      fonts: [],
      families: { sans: 'Inter' },
      groups: [{ name: 'A', family: 'serif', styles: [] }],
    };
    expect(() => parseTokens(raw)).toThrow(
      "type.groups[0] uses unknown family 'serif'",
    );
  });

  it('rejects a top-level section of an unknown shape', () => {
    const raw = fixture();
    raw.motion = { durations: [{ name: 'fast', value: '150ms' }] };
    expect(() => parseTokens(raw)).toThrow(
      `top-level 'motion' is not a {"tokens": [...]} section`,
    );
  });

  it('rejects an unknown key in a section', () => {
    const raw = fixture();
    raw.spacing = { tokens: [], scale: 4 };
    expect(() => parseTokens(raw)).toThrow("spacing has unknown key 'scale'");
  });

  it('rejects an alias outside the colours', () => {
    const raw = fixture();
    raw.spacing = { tokens: [{ name: 'gutter', value: '{space-4}' }] };
    expect(() => parseTokens(raw)).toThrow(
      "token 'gutter' is an alias; only colours may alias",
    );
  });

  it('rejects a value that would end its declaration', () => {
    const raw = fixture();
    raw.spacing = { tokens: [{ name: 'gutter', value: '4px; color: red' }] };
    expect(() => parseTokens(raw)).toThrow(
      "token 'gutter' value has an unsupported value '4px; color: red'",
    );
  });

  it('rejects declared font files', () => {
    const raw = fixture();
    raw.type = { fonts: [{ family: 'Inter' }], families: {}, groups: [] };
    expect(() => parseTokens(raw)).toThrow('type.fonts is not supported');
  });

  it('rejects a type style size that is not a length', () => {
    const raw = fixture();
    raw.type = {
      fonts: [],
      families: { sans: 'Inter' },
      groups: [
        {
          name: 'A',
          family: 'sans',
          styles: [
            {
              name: 'body',
              fontSize: 'large',
              lineHeight: '22px',
              fontWeight: 400,
            },
          ],
        },
      ],
    };
    expect(() => parseTokens(raw)).toThrow(
      "type style 'body' fontSize 'large' is not a px, em or rem length",
    );
  });
});

describe('the committed tokens.css', () => {
  it('is up to date with tokens.json', () => {
    expect(readFileSync(TOKENS_CSS, 'utf8')).toBe(buildTokensCss());
  });

  it('passes the build check', () => {
    const result = spawnSync(
      process.execPath,
      ['scripts/build-tokens.ts', '--check'],
      { cwd: FRONTEND, encoding: 'utf8' },
    );
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
  });

  it('has a class for every type style of the design system', () => {
    const css = buildTokensCss();
    for (const name of [
      'display',
      'h1',
      'h2',
      'h2-mobile',
      'h3',
      'h4',
      'body',
      'body-dense',
      'input-mobile',
      'small',
      'label',
      'caption',
      'mono',
      'photo-id',
      'frame-number',
      'mono-label',
      'mono-caption',
      'score-numeral',
      'photo-title',
      'score-key',
      'key-cap',
      'key-hint',
    ]) {
      expect(classBlock(css, name), name).toBeDefined();
    }
  });
});
