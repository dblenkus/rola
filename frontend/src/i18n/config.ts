import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

i18n.use(LanguageDetector)
    .use(initReactI18next)
    .init({
        fallbackLng: 'en',
        resources: {
            en: {
                translations: require('./locales/en/translations.json'),
            },
            sl: {
                translations: require('./locales/sl/translations.json'),
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

i18n.languages = ['en', 'sl'];

export default i18n;
