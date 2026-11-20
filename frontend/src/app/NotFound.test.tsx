import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it } from 'vitest';
import { apiClient } from '../shared/api/client';
import { open } from '../test/app';

beforeEach(() => {
  localStorage.clear();
  apiClient.defaults.adapter = () => new Promise(() => {});
});

it('says that an unknown location has no page and links home', async () => {
  const user = userEvent.setup();
  open('/no/such/page');
  const main = screen.getByRole('main');
  expect(
    within(main).getByRole('heading', { level: 1, name: 'Page not found' }),
  ).toBeInTheDocument();
  expect(document.title).toBe('Page not found · Rola');
  expect(screen.getByRole('banner')).toBeInTheDocument();
  await user.click(
    within(main).getByRole('link', { name: 'Go to the home page' }),
  );
  expect(window.location.pathname).toBe('/contests');
});
