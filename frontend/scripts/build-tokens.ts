/**
 * Write src/design/tokens.css from src/design/tokens.json.
 *
 * Usage: node scripts/build-tokens.ts [--check]
 * With --check nothing is written; the script exits 1 if tokens.css is out of
 * date.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import { parseTokens, renderTokensCss } from './tokens.ts';

export const TOKENS_JSON = new URL(
  '../src/design/tokens.json',
  import.meta.url,
);
export const TOKENS_CSS = new URL('../src/design/tokens.css', import.meta.url);

export function buildTokensCss(): string {
  const raw: unknown = JSON.parse(readFileSync(TOKENS_JSON, 'utf8'));
  return renderTokensCss(parseTokens(raw));
}

function readCurrent(): string | null {
  try {
    return readFileSync(TOKENS_CSS, 'utf8');
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

function main(): void {
  const { values } = parseArgs({
    options: { check: { type: 'boolean', default: false } },
  });
  const css = buildTokensCss();
  if (values.check) {
    if (readCurrent() !== css) {
      console.error(
        'src/design/tokens.css is out of date. Run `npm run tokens`.',
      );
      process.exit(1);
    }
    process.stdout.write('src/design/tokens.css is up to date.\n');
    return;
  }
  writeFileSync(TOKENS_CSS, css);
  process.stdout.write('Wrote src/design/tokens.css.\n');
}

if (import.meta.main) {
  main();
}
