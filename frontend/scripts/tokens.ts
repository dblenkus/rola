/**
 * Render the Rola design tokens (src/design/tokens.json, copied from the
 * design system) as CSS custom properties and type-style classes. Any shape
 * this renderer does not know throws, so a changed design-system export is
 * noticed instead of silently dropped or guessed at.
 */

export interface NamedToken {
  name: string;
  value: string;
}

export interface TypeStyle {
  name: string;
  family: string;
  fontSize: string;
  lineHeight: string;
  fontWeight: number;
  letterSpacing?: string;
}

export interface Tokens {
  colors: NamedToken[];
  families: NamedToken[];
  /** Every `{"tokens": [...]}` section other than colour, in file order. */
  scales: { section: string; tokens: NamedToken[] }[];
  typeStyles: TypeStyle[];
}

const THEMES = ['light'];
const NAME = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;
const ALIAS = /^\{([^{}]*)\}$/;
const HEX_COLOR = /^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;
const LENGTH = /^-?\d+(\.\d+)?(px|em|rem)$/;
// A value is written into a declaration as is, so it must not close it.
const UNSAFE_VALUE = /[;{}]|\/\*|\*\//;

const METADATA_KEYS = ['name', 'version'];
const SECTION_KEYS = ['tokens', 'note'];
const TOKEN_KEYS = ['name', 'value', 'usage'];
const STYLE_KEYS = [
  'name',
  'fontSize',
  'lineHeight',
  'fontWeight',
  'letterSpacing',
  'sample',
  'usage',
];

function fail(message: string): never {
  throw new Error(`tokens.json: ${message}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown, where: string): Record<string, unknown> {
  if (!isRecord(value)) fail(`${where} must be an object`);
  return value;
}

function asArray(value: unknown, where: string): unknown[] {
  if (!Array.isArray(value)) fail(`${where} must be an array`);
  return value;
}

function asString(value: unknown, where: string): string {
  if (typeof value !== 'string' || value === '') {
    fail(`${where} must be a non-empty string`);
  }
  return value;
}

function onlyKeys(
  record: Record<string, unknown>,
  allowed: string[],
  where: string,
): void {
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) fail(`${where} has unknown key '${key}'`);
  }
}

function asName(value: unknown, where: string): string {
  const name = asString(value, where);
  if (!NAME.test(name)) fail(`${where} '${name}' is not a CSS-safe name`);
  return name;
}

function asCssValue(value: unknown, where: string): string {
  const text = asString(value, where);
  if (UNSAFE_VALUE.test(text))
    fail(`${where} has an unsupported value '${text}'`);
  return text;
}

function asLength(value: unknown, where: string): string {
  const text = asString(value, where);
  if (!LENGTH.test(text))
    fail(`${where} '${text}' is not a px, em or rem length`);
  return text;
}

function parseToken(raw: unknown, where: string): NamedToken {
  const token = asRecord(raw, where);
  onlyKeys(token, TOKEN_KEYS, where);
  const name = asName(token.name, `${where}.name`);
  return { name, value: asString(token.value, `token '${name}' value`) };
}

function parseColors(raw: unknown): NamedToken[] {
  const color = asRecord(raw, 'color');
  onlyKeys(color, ['themes', 'tokens'], 'color');
  const themes = asArray(color.themes, 'color.themes').map((theme, index) =>
    asString(
      asRecord(theme, `color.themes[${index}]`).id,
      `color.themes[${index}].id`,
    ),
  );
  if (themes.join(',') !== THEMES.join(',')) {
    fail(
      `color.themes must be exactly ${THEMES.join(', ')}, got ${themes.join(', ')}`,
    );
  }
  const tokens = asArray(color.tokens, 'color.tokens').map((token, index) =>
    parseToken(token, `color.tokens[${index}]`),
  );
  const names = new Set(tokens.map((token) => token.name));
  for (const { name, value } of tokens) {
    const alias = ALIAS.exec(value);
    if (alias) {
      const target = alias[1] ?? '';
      if (!names.has(target)) {
        fail(`colour '${name}' is an alias of unknown colour '${target}'`);
      }
    } else if (!HEX_COLOR.test(value)) {
      fail(
        `colour '${name}' value '${value}' is neither a hex colour nor an alias`,
      );
    }
  }
  for (const { name } of tokens) {
    resolveColor(tokens, name);
  }
  return tokens;
}

/** Follow a colour's aliases to its literal; throws on an alias cycle. */
function resolveColor(colors: NamedToken[], name: string): string {
  const seen: string[] = [];
  let current = name;
  for (;;) {
    if (seen.includes(current)) {
      fail(
        `colour '${name}' has an alias cycle: ${[...seen, current].join(' -> ')}`,
      );
    }
    seen.push(current);
    const token = colors.find((candidate) => candidate.name === current);
    if (token === undefined) fail(`unknown colour '${current}'`);
    const alias = ALIAS.exec(token.value);
    if (!alias) return token.value;
    current = alias[1] ?? '';
  }
}

function parseType(raw: unknown): Pick<Tokens, 'families' | 'typeStyles'> {
  const type = asRecord(raw, 'type');
  onlyKeys(type, ['fonts', 'families', 'groups'], 'type');
  if (asArray(type.fonts, 'type.fonts').length > 0) {
    fail('type.fonts is not supported; fonts.css declares the font faces');
  }
  const families = Object.entries(asRecord(type.families, 'type.families')).map(
    ([family, stack]) => ({
      name: asName(family, 'type.families key'),
      value: asCssValue(stack, `type family '${family}'`),
    }),
  );
  const familyNames = families.map((family) => family.name);
  const typeStyles = asArray(type.groups, 'type.groups').flatMap(
    (rawGroup, groupIndex) => {
      const where = `type.groups[${groupIndex}]`;
      const group = asRecord(rawGroup, where);
      onlyKeys(group, ['name', 'family', 'styles'], where);
      const family = asString(group.family, `${where}.family`);
      if (!familyNames.includes(family)) {
        fail(`${where} uses unknown family '${family}'`);
      }
      return asArray(group.styles, `${where}.styles`).map((rawStyle, index) =>
        parseTypeStyle(rawStyle, family, `${where}.styles[${index}]`),
      );
    },
  );
  return { families, typeStyles };
}

function parseTypeStyle(
  raw: unknown,
  family: string,
  where: string,
): TypeStyle {
  const style = asRecord(raw, where);
  onlyKeys(style, STYLE_KEYS, where);
  const name = asName(style.name, `${where}.name`);
  const { fontWeight } = style;
  if (
    typeof fontWeight !== 'number' ||
    !Number.isInteger(fontWeight) ||
    fontWeight < 1 ||
    fontWeight > 1000
  ) {
    fail(`type style '${name}' fontWeight must be an integer from 1 to 1000`);
  }
  const parsed: TypeStyle = {
    name,
    family,
    fontSize: asLength(style.fontSize, `type style '${name}' fontSize`),
    lineHeight: asLength(style.lineHeight, `type style '${name}' lineHeight`),
    fontWeight,
  };
  if (style.letterSpacing !== undefined) {
    parsed.letterSpacing = asLength(
      style.letterSpacing,
      `type style '${name}' letterSpacing`,
    );
  }
  return parsed;
}

function parseScale(section: string, raw: unknown): NamedToken[] {
  const record = asRecord(raw, section);
  onlyKeys(record, SECTION_KEYS, section);
  return asArray(record.tokens, `${section}.tokens`).map((token, index) => {
    const parsed = parseToken(token, `${section}.tokens[${index}]`);
    if (ALIAS.test(parsed.value)) {
      fail(`token '${parsed.name}' is an alias; only colours may alias`);
    }
    return {
      name: parsed.name,
      value: asCssValue(parsed.value, `token '${parsed.name}' value`),
    };
  });
}

function requireUnique(names: string[], what: string): void {
  const seen = new Set<string>();
  for (const name of names) {
    if (seen.has(name)) fail(`duplicate ${what} '${name}'`);
    seen.add(name);
  }
}

export function parseTokens(raw: unknown): Tokens {
  const root = asRecord(raw, 'root');
  const scales: Tokens['scales'] = [];
  for (const [section, value] of Object.entries(root)) {
    if (
      METADATA_KEYS.includes(section) ||
      section === 'color' ||
      section === 'type'
    ) {
      continue;
    }
    if (!isRecord(value) || !('tokens' in value)) {
      fail(`top-level '${section}' is not a {"tokens": [...]} section`);
    }
    scales.push({ section, tokens: parseScale(section, value) });
  }
  const tokens: Tokens = {
    colors: parseColors(root.color),
    ...parseType(root.type),
    scales,
  };
  requireUnique(
    [
      ...tokens.colors.map((token) => token.name),
      ...tokens.families.map((family) => `font-${family.name}`),
      ...tokens.scales.flatMap((scale) =>
        scale.tokens.map((token) => token.name),
      ),
    ],
    'custom property',
  );
  requireUnique(
    tokens.typeStyles.map((style) => style.name),
    'type style',
  );
  return tokens;
}

function declaration(name: string, value: string): string {
  return `  --${name}: ${value};`;
}

export function renderTokensCss(tokens: Tokens): string {
  const colorValue = (value: string): string => {
    const alias = ALIAS.exec(value);
    return alias ? `var(--${alias[1] ?? ''})` : value;
  };
  const properties = [
    '  color-scheme: light;',
    '',
    '  /* color */',
    ...tokens.colors.map(({ name, value }) =>
      declaration(name, colorValue(value)),
    ),
    '',
    '  /* type families */',
    ...tokens.families.map(({ name, value }) =>
      declaration(`font-${name}`, value),
    ),
    ...tokens.scales.flatMap(({ section, tokens: scale }) => [
      '',
      `  /* ${section} */`,
      ...scale.map(({ name, value }) => declaration(name, value)),
    ]),
  ];
  const classes = tokens.typeStyles.map((style) =>
    [
      `.${style.name} {`,
      `  font-family: var(--font-${style.family});`,
      `  font-size: ${style.fontSize};`,
      `  line-height: ${style.lineHeight};`,
      `  font-weight: ${style.fontWeight};`,
      ...(style.letterSpacing === undefined
        ? []
        : [`  letter-spacing: ${style.letterSpacing};`]),
      '}',
    ].join('\n'),
  );
  return [
    '/* Generated from tokens.json by scripts/build-tokens.ts. Do not edit; run `npm run tokens`. */',
    '',
    `:root {\n${properties.join('\n')}\n}`,
    '',
    '/* Type styles: one class per style, setting no colour. */',
    '',
    classes.join('\n\n'),
    '',
  ].join('\n');
}
