import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';
import { apiClient } from '../../shared/api/client';
import { serveApi, signIn } from '../../test/api';
import { open } from '../../test/app';
import store from '../store';
import { authorUpdate } from '../../features/upload/state/actions';

beforeEach(() => {
  localStorage.clear();
  apiClient.defaults.adapter = () => new Promise(() => {});
});

const trigger = () =>
  screen.getByRole('button', { name: 'account of current user' });

describe('signed out', () => {
  it("is drawn as the app bar's account button", () => {
    open('/contests');
    expect(trigger()).toHaveClass('rl-appbar__account');
    expect(trigger().querySelector('svg.rl-appbar__chevron')).not.toBeNull();
  });

  it('offers registration and login', async () => {
    const user = userEvent.setup();
    open('/contests');
    await user.click(trigger());
    expect(
      screen.getAllByRole('menuitem').map((item) => item.textContent),
    ).toEqual(['Register', 'Login']);
    await user.click(screen.getByRole('menuitem', { name: 'Register' }));
    expect(window.location.pathname).toBe('/register');
  });

  it('returns from login to the page it was opened on', async () => {
    serveApi({
      'POST /user/login': () => ({
        token: 'signed-in',
        expires: '2999-01-01T00:00:00Z',
      }),
      'GET /contest': () => new Promise(() => {}),
    });
    const user = userEvent.setup();
    open('/results?page=2');
    await user.click(trigger());
    await user.click(screen.getByRole('menuitem', { name: 'Login' }));
    expect(window.location.pathname).toBe('/login');
    await user.type(
      await screen.findByRole('textbox', { name: /email/i }),
      'ana@example.com',
    );
    await user.type(screen.getByLabelText(/password/i), 'example-password');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    await waitFor(() => expect(window.location.pathname).toBe('/results'));
    expect(window.location.search).toBe('?page=2');
  });
});

describe('signed in', () => {
  it("shows the account's initial and email", () => {
    signIn('signed-in', 'ana@example.com');
    open('/contests');
    expect(trigger()).toHaveTextContent('Aana@example.com');
  });

  it("is drawn as the app bar's account button", () => {
    signIn('signed-in', 'ana@example.com');
    open('/contests');
    const button = trigger();
    expect(button).toHaveClass('rl-appbar__account');
    expect(button).not.toHaveClass('rl-btn');
    expect(button.querySelector('.rl-appbar__avatar')).toHaveTextContent('A');
    expect(button.querySelector('svg.rl-appbar__chevron')).not.toBeNull();
  });

  it('offers the profile and logout', async () => {
    signIn();
    const user = userEvent.setup();
    open('/contests');
    await user.click(trigger());
    expect(
      screen.getAllByRole('menuitem').map((item) => item.textContent),
    ).toEqual(['Profile', 'Logout']);
    await user.click(screen.getByRole('menuitem', { name: 'Profile' }));
    await waitFor(() =>
      expect(screen.queryByRole('menu')).not.toBeInTheDocument(),
    );
    expect(localStorage.getItem('token')).not.toBeNull();
  });

  it('logs out and forgets the upload form', async () => {
    signIn();
    store.dispatch(authorUpdate({ name: 'first_name', value: 'Ana' }));
    expect(store.getState().upload.contest.author.first_name).toBe('Ana');
    const user = userEvent.setup();
    open('/contests');
    await user.click(trigger());
    await user.click(screen.getByRole('menuitem', { name: 'Logout' }));
    expect(localStorage.getItem('token')).toBeNull();
    expect(store.getState().upload.contest.author.first_name).toBe('');
    await user.click(trigger());
    expect(
      screen.getAllByRole('menuitem').map((item) => item.textContent),
    ).toEqual(['Register', 'Login']);
  });
});
