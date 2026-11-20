import { describe, expect, it } from 'vitest';
import english from './locales/en/translations.json';
import slovenian from './locales/sl/translations.json';

const locales: [string, Record<string, string>][] = [
  ['en', english],
  ['sl', slovenian],
];

const pluralSuffix = /_(zero|one|two|few|many|other)$/;

// The plural forms that each pluralised key has, by its key without the
// suffix.
function pluralForms(translations: Record<string, string>) {
  const forms = new Map<string, string[]>();
  for (const key of Object.keys(translations)) {
    const match = pluralSuffix.exec(key);
    if (match?.[1]) {
      const base = key.slice(0, match.index);
      forms.set(base, [...(forms.get(base) ?? []), match[1]].sort());
    }
  }
  return forms;
}

// The keys a translation is looked up by: plural forms count as their base.
function lookupKeys(translations: Record<string, string>): string[] {
  return [
    ...new Set(
      Object.keys(translations).map((key) => key.replace(pluralSuffix, '')),
    ),
  ].sort();
}

describe('translations', () => {
  it('translate the same keys in every language', () => {
    expect(lookupKeys(slovenian)).toEqual(lookupKeys(english));
  });

  it.each(locales)('leave no %s text empty', (_language, translations) => {
    const empty = Object.entries(translations)
      .filter(([, text]) => !text.trim())
      .map(([key]) => key);
    expect(empty).toEqual([]);
  });

  it.each(locales)(
    'give each %s plural every form the language has',
    (language, translations) => {
      const categories = [
        ...new Intl.PluralRules(language).resolvedOptions().pluralCategories,
      ].sort();
      for (const [base, forms] of pluralForms(translations)) {
        expect({ base, forms }).toEqual({ base, forms: categories });
      }
    },
  );
});
