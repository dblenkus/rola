import { render, screen } from '@testing-library/react';
import i18next from 'i18next';
import { I18nextProvider, initReactI18next } from 'react-i18next';
import { expect, it } from 'vitest';
import LoadingProgress from './LoadingProgress';

const i18n = i18next.createInstance();
await i18n.use(initReactI18next).init({
  lng: 'en',
  resources: { en: { translation: { ui_loading: 'Loading' } } },
});

it('is a progress indicator named in the interface language, without a value', () => {
  render(
    <I18nextProvider i18n={i18n}>
      <LoadingProgress />
    </I18nextProvider>,
  );
  const progress = screen.getByRole('progressbar', { name: 'Loading' });
  expect(progress).toHaveTextContent('Loading');
  expect(progress).not.toHaveAttribute('aria-valuenow');
  expect(progress).not.toHaveAttribute('aria-valuemax');
  // The mark is decorative: the word names the indicator.
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
});
