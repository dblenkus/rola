import english from './locales/en/translations.json';
import slovenian from './locales/sl/translations.json';
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

// The document's language follows the interface's, for screen readers,
// hyphenation and the browser's translation offer. Registered before init,
// which emits the detected language as the first change.
i18n.on('languageChanged', (language) => {
  document.documentElement.lang = language;
});

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: 'en',
    supportedLngs: ['en', 'sl'],
    interpolation: { escapeValue: false },
    resources: {
      en: {
        translations: english,
      },
      sl: {
        translations: slovenian,
      },
    },
    ns: ['translations'],
    defaultNS: 'translations',
    detection: {
      lookupQuerystring: 'lang',
      lookupCookie: 'lang',
      lookupLocalStorage: 'lang',
    },
  });

export default i18n;
