import type { ReactNode } from 'react';
import { I18nProvider, RouterProvider } from 'react-aria-components';
import { useTranslation } from 'react-i18next';
import { useHref, useNavigate } from 'react-router';

// The React Aria locale of each interface language: it sets the formats of
// dates and numbers in the kit's fields.
const ariaLocales: Record<string, string> = { sl: 'sl-SI', en: 'en-GB' };

export function ariaLocale(language: string | undefined): string {
  const locale = language === undefined ? undefined : ariaLocales[language];
  if (locale === undefined) {
    throw new Error(`No React Aria locale for the language "${language}"`);
  }
  return locale;
}

// Gives the React Aria components the interface's locale, following language
// changes, and the router, so their links navigate without reloading the
// page. Render it inside the router.
export default function AriaProviders({ children }: { children: ReactNode }) {
  const { i18n } = useTranslation();
  const navigate = useNavigate();
  return (
    <RouterProvider navigate={navigate} useHref={useHref}>
      <I18nProvider locale={ariaLocale(i18n.resolvedLanguage)}>
        {children}
      </I18nProvider>
    </RouterProvider>
  );
}
