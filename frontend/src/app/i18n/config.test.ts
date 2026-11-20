import { expect, it, onTestFinished } from 'vitest';
import i18n from './config';

it('starts in English, as jsdom reports, and marks the document so', () => {
  expect(i18n.language).toBe('en');
  expect(document.documentElement.lang).toBe('en');
});

it('marks the document with the language the interface changes to', async () => {
  onTestFinished(async () => {
    await i18n.changeLanguage('en');
  });
  await i18n.changeLanguage('sl');
  expect(document.documentElement.lang).toBe('sl');
  await i18n.changeLanguage('en');
  expect(document.documentElement.lang).toBe('en');
});

it('falls back to English', () => {
  expect(i18n.options.fallbackLng).toEqual(['en']);
});
