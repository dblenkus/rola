import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it } from 'vitest';
import i18n from '../i18n/config';
import { apiClient } from '../../shared/api/client';
import { open } from '../../test/app';

beforeEach(() => {
  localStorage.clear();
  apiClient.defaults.adapter = () => new Promise(() => {});
});

afterEach(async () => {
  await i18n.changeLanguage('en');
  localStorage.clear();
});

it('offers both languages, each named in itself, the current one pressed', () => {
  open('/contests');
  const group = screen.getByRole('group', { name: 'Language' });
  const slovenian = within(group).getByRole('button', { name: 'Slovenščina' });
  const english = within(group).getByRole('button', { name: 'English' });
  expect(slovenian).toHaveTextContent('SL');
  expect(slovenian).toHaveAttribute('lang', 'sl');
  expect(slovenian).toHaveAttribute('aria-pressed', 'false');
  expect(english).toHaveTextContent('EN');
  expect(english).toHaveAttribute('lang', 'en');
  expect(english).toHaveAttribute('aria-pressed', 'true');
  expect(group).toHaveTextContent('SL/EN');
});

it('switches the interface and the document language', async () => {
  const user = userEvent.setup();
  open('/contests');
  await user.click(screen.getByRole('button', { name: 'Slovenščina' }));
  expect(document.documentElement.lang).toBe('sl');
  const group = screen.getByRole('group', { name: 'Jezik' });
  expect(
    within(group).getByRole('button', { name: 'Slovenščina' }),
  ).toHaveAttribute('aria-pressed', 'true');
  expect(
    within(group).getByRole('button', { name: 'English' }),
  ).toHaveAttribute('aria-pressed', 'false');
  const nav = screen.getByRole('navigation', { name: 'Glavna navigacija' });
  for (const name of ['Aktivni natečaji', 'Urejanje prijav', 'Rezultati']) {
    expect(within(nav).getByRole('link', { name })).toBeInTheDocument();
  }

  await user.click(within(group).getByRole('button', { name: 'English' }));
  expect(document.documentElement.lang).toBe('en');
  expect(
    screen.getByRole('link', { name: 'Active contests' }),
  ).toBeInTheDocument();
});
