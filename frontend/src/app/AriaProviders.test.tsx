import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it } from 'vitest';
import { Link as AriaLink, useLocale } from 'react-aria-components';
import { MemoryRouter, Route, Routes } from 'react-router';
import i18n from './i18n/config';
import AriaProviders, { ariaLocale } from './AriaProviders';

function ShowLocale() {
  return <p>{useLocale().locale}</p>;
}

function renderProviders() {
  render(
    <MemoryRouter initialEntries={['/start']}>
      <AriaProviders>
        <ShowLocale />
        <AriaLink href="/next">Next</AriaLink>
        <Routes>
          <Route path="/start" element={<p>Start page</p>} />
          <Route path="/next" element={<p>Next page</p>} />
        </Routes>
      </AriaProviders>
    </MemoryRouter>,
  );
}

afterEach(async () => {
  await i18n.changeLanguage('en');
  localStorage.clear();
});

it('gives React Aria the locale of the interface language', async () => {
  renderProviders();
  expect(screen.getByText('en-GB')).toBeInTheDocument();
  await act(() => i18n.changeLanguage('sl'));
  expect(screen.getByText('sl-SI')).toBeInTheDocument();
});

it('refuses a language without a locale', () => {
  expect(() => ariaLocale('de')).toThrow('No React Aria locale');
  expect(() => ariaLocale(undefined)).toThrow('No React Aria locale');
});

it('navigates React Aria links through the router', async () => {
  const user = userEvent.setup();
  renderProviders();
  const link = screen.getByRole('link', { name: 'Next' });
  expect(link).toHaveAttribute('href', '/next');
  await user.click(link);
  expect(screen.getByText('Next page')).toBeInTheDocument();
});
