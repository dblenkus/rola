import { Fragment } from 'react';
import { useTranslation } from 'react-i18next';

// Each language is named in itself, as the person who needs it reads it.
const languages = [
  { code: 'sl', short: 'SL', name: 'Slovenščina' },
  { code: 'en', short: 'EN', name: 'English' },
] as const;

// "SL / EN": both languages, the current one pressed.
export default function LanguageSwitch() {
  const { i18n, t } = useTranslation();
  return (
    <div
      className="rl-appbar__lang"
      role="group"
      aria-label={t('shell_language')}
    >
      {languages.map(({ code, short, name }, index) => (
        <Fragment key={code}>
          {index > 0 && (
            <span className="rl-appbar__lang-sep" aria-hidden="true">
              /
            </span>
          )}
          <button
            type="button"
            className="rl-appbar__lang-option shell-lang-option"
            lang={code}
            aria-label={name}
            aria-pressed={i18n.resolvedLanguage === code}
            onClick={() => void i18n.changeLanguage(code)}
          >
            {short}
          </button>
        </Fragment>
      ))}
    </div>
  );
}
