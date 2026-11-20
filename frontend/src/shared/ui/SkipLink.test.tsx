import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import i18next from 'i18next';
import { I18nextProvider, initReactI18next } from 'react-i18next';
import { expect, it } from 'vitest';
import SkipLink from './SkipLink';

const i18n = i18next.createInstance();
await i18n.use(initReactI18next).init({
  lng: 'en',
  resources: { en: { translation: { ui_skip_to_content: 'Skip to content' } } },
});

it('is the first tab stop and moves focus to the main content', async () => {
  const user = userEvent.setup();
  render(
    <I18nextProvider i18n={i18n}>
      <SkipLink />
      <header>
        <a href="/">Home</a>
      </header>
      <main id="main" tabIndex={-1}>
        Content
      </main>
    </I18nextProvider>,
  );
  await user.tab();
  const link = screen.getByRole('link', { name: 'Skip to content' });
  expect(link).toHaveFocus();
  expect(link).toHaveAttribute('href', '#main');
  await user.keyboard('{Enter}');
  expect(screen.getByRole('main')).toHaveFocus();
  expect(window.location.hash).toBe('');
});
