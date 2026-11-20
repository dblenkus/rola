import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';
import './i18n/config';
import { apiClient } from '../shared/api/client';
import store from './store';
import { deleteMessage } from '../features/notifications/state/actions';
import {
  blockStorage,
  httpError,
  networkError,
  page,
  serveApi,
  signIn,
  withStatus,
} from '../test/api';
import { open } from '../test/app';
import { contest, jurySubmission } from '../test/fixtures';
import headerReversedUrl from '../design/logos/rola-logo-header-reversed.svg';
import headerUrl from '../design/logos/rola-logo-header.svg';

beforeEach(() => {
  localStorage.clear();
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
});

describe('sessions', () => {
  it('sends a revoked session to login and removes its credentials', async () => {
    signIn('revoked');
    apiClient.defaults.adapter = async (config) => {
      throw httpError(config, 401);
    };
    open('/contest/1/upload');
    expect(
      await screen.findByRole('textbox', { name: /email/i }),
    ).toBeInTheDocument();
    expect(localStorage.getItem('token')).toBeNull();
    expect(window.location.pathname).toBe('/login');
  });

  it('loads public contests after the server rejects the stored token', async () => {
    signIn('revoked');
    const sent: unknown[] = [];
    serveApi({
      'GET /contests': (config) => {
        sent.push(config.headers.get('Authorization'));
        if (config.headers.has('Authorization')) {
          throw httpError(config, 401, { detail: 'Token has expired.' });
        }
        return page([contest]);
      },
    });
    open('/contests');
    expect(
      await screen.findByRole('heading', { name: contest.title }),
    ).toBeInTheDocument();
    expect(sent).toEqual(['Bearer revoked', undefined]);
    expect(localStorage.getItem('token')).toBeNull();
    expect(window.location.pathname).toBe('/contests');
  });

  it('lists public contests when site storage is blocked', async () => {
    blockStorage();
    serveApi({ 'GET /contests': () => page([contest]) });
    open('/contests');
    expect(
      await screen.findByRole('heading', { name: contest.title }),
    ).toBeInTheDocument();
  });

  it('refuses a login that site storage cannot keep', async () => {
    blockStorage();
    const adapter = serveApi({
      'POST /tokens': () =>
        withStatus(201, {
          token: 'signed-in',
          expires: '2999-01-01T00:00:00Z',
        }),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await user.type(
      await screen.findByRole('textbox', { name: /email/i }),
      'ana@example.com',
    );
    await user.type(screen.getByLabelText(/password/i), 'example-password');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(
      await screen.findByText(
        'Signing in needs site storage. Allow this site to store data, then try again.',
      ),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/login');
    expect(
      adapter.mock.calls.map(([config]) => [
        `${config.method} ${config.url}`,
        config.headers.get('Authorization'),
      ]),
    ).toEqual([['post /tokens', undefined]]);
  });

  it('keeps a later login when the API rejects the logout before it', async () => {
    signIn('earlier');
    const rejectLogout: (() => void)[] = [];
    serveApi({
      'GET /contests': () => page([contest]),
      'DELETE /tokens/current': (config) =>
        new Promise((_resolve, reject) => {
          rejectLogout.push(() =>
            reject(httpError(config, 401, { detail: 'Token has expired' })),
          );
        }),
      'POST /tokens': () =>
        withStatus(201, {
          token: 'later',
          expires: '2999-01-01T00:00:00Z',
        }),
    });
    const user = userEvent.setup();
    open('/contests');
    const account = screen.getByRole('button', {
      name: 'account of current user',
    });
    await user.click(account);
    await user.click(screen.getByRole('menuitem', { name: 'Logout' }));
    await user.click(account);
    await user.click(screen.getByRole('menuitem', { name: 'Login' }));
    await user.type(
      await screen.findByRole('textbox', { name: /email/i }),
      'ana@example.com',
    );
    await user.type(screen.getByLabelText(/password/i), 'example-password');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(
      await screen.findByRole('heading', { name: contest.title }),
    ).toBeInTheDocument();
    const later = localStorage.getItem('token');
    expect(JSON.parse(later ?? 'null')).toMatchObject({ token: 'later' });
    expect(rejectLogout).toHaveLength(1);
    // Vitest fails the run if nothing handles the rejected request.
    rejectLogout.forEach((reject) => reject());
    await user.click(account);
    expect(
      screen.getByRole('menuitem', { name: 'Logout' }),
    ).toBeInTheDocument();
    expect(localStorage.getItem('token')).toBe(later);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('stays logged out when the logout request gets no response', async () => {
    signIn();
    const adapter = serveApi({
      'GET /contests': () => page([contest]),
      // Vitest fails the run if nothing handles the failed request.
      'DELETE /tokens/current': (config) => {
        throw networkError(config);
      },
    });
    const user = userEvent.setup();
    open('/contests');
    const account = screen.getByRole('button', {
      name: 'account of current user',
    });
    await user.click(account);
    await user.click(screen.getByRole('menuitem', { name: 'Logout' }));
    expect(
      await screen.findByText('Network error occurred.'),
    ).toBeInTheDocument();
    expect(
      adapter.mock.calls.filter(([config]) => config.url === '/tokens/current'),
    ).toHaveLength(1);
    expect(localStorage.getItem('token')).toBeNull();
    await user.click(account);
    expect(screen.getByRole('menuitem', { name: 'Login' })).toBeInTheDocument();
  });

  it('returns to the full requested location after login', async () => {
    serveApi({
      'POST /tokens': () =>
        withStatus(201, {
          token: 'signed-in',
          expires: '2999-01-01T00:00:00Z',
        }),
      'GET /contests/1': () => contest,
      'GET /judging/submissions': () =>
        page([
          jurySubmission(11, 'First photograph'),
          jurySubmission(12, 'Second'),
        ]),
      'GET /judging/ratings': () => page([]),
    });
    const user = userEvent.setup();
    open('/judge/contest/1/theme/2/rate?submission=12');
    const entries = window.history.length;
    await user.type(
      await screen.findByRole('textbox', { name: /email/i }),
      'judge@example.com',
    );
    await user.type(screen.getByLabelText(/password/i), 'example-password');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(
      await screen.findByRole('img', { name: 'Second' }),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/judge/contest/1/theme/2/rate');
    expect(window.location.search).toBe('?submission=12');
    expect(window.history.length).toBe(entries);
  });
});
describe('account requests', () => {
  it('rejects a missing reset token without sending a request', async () => {
    const adapter = serveApi({});
    open('/password-reset');
    const user = userEvent.setup();
    await user.type(
      await screen.findByLabelText(/new password/i),
      'Replacement!73',
    );
    await user.click(screen.getByRole('button', { name: /password reset/i }));
    expect(
      await screen.findByText('Invalid password reset token.'),
    ).toBeInTheDocument();
    expect(adapter).not.toHaveBeenCalled();
  });

  it('does not send an activation request without a token', async () => {
    const adapter = serveApi({});
    open('/register/activate');
    expect(
      await screen.findByText('Account activation failed!'),
    ).toBeInTheDocument();
    expect(adapter).not.toHaveBeenCalled();
  });

  it('reports a throttled activation instead of an invalid token', async () => {
    serveApi({
      'POST /activations': (config) => {
        throw httpError(
          config,
          429,
          { detail: 'Request was throttled.' },
          { 'retry-after': '3600' },
        );
      },
    });
    open('/register/activate?token=signed-token');
    expect(
      await screen.findByText(
        'Too many requests from this network. Please try again in 60 minutes.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText('Invalid token.')).not.toBeInTheDocument();
  });

  it('reports an invalid activation token', async () => {
    serveApi({
      'POST /activations': (config) => {
        throw httpError(config, 400, { non_field_errors: ['Bad token.'] });
      },
    });
    open('/register/activate?token=forged-token');
    expect(
      await screen.findByText('Account activation failed!'),
    ).toBeInTheDocument();
    expect(screen.getByText('Invalid token.')).toBeInTheDocument();
  });

  it('clears a failed reset request after a successful retry', async () => {
    let attempts = 0;
    serveApi({
      'POST /password-reset-requests': (config) => {
        attempts += 1;
        if (attempts === 1) {
          throw httpError(config, 429, { detail: 'Request was throttled.' });
        }
        return withStatus(202, '');
      },
    });
    const user = userEvent.setup();
    open('/password-reset/request');
    await user.type(
      await screen.findByRole('textbox', { name: /email/i }),
      'participant@example.com',
    );
    const submit = screen.getByRole('button', { name: /password reset/i });
    await user.click(submit);
    expect(
      await screen.findByText(
        'Too many requests from this network. Please try again later.',
      ),
    ).toBeInTheDocument();
    await user.click(submit);
    expect(
      await screen.findByText('Email sent to participant@example.com'),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(
        'Too many requests from this network. Please try again later.',
      ),
    ).not.toBeInTheDocument();
  });
});

describe('sign-in pages', () => {
  it.each(['/login', '/register', '/password-reset/request'])(
    'shows the logo only in the app bar on %s',
    async (path) => {
      open(path);
      expect(
        await screen.findByRole('heading', { level: 1 }),
      ).toBeInTheDocument();
      // The app bar's lockup is its ink file and its white file, of which
      // CSS shows the one for the ground; jsdom applies no CSS.
      const images = Array.from(document.querySelectorAll('img'));
      expect(images.map((image) => image.getAttribute('src'))).toEqual([
        headerUrl,
        headerReversedUrl,
      ]);
      for (const image of images) {
        expect(screen.getByRole('banner')).toContainElement(image);
      }
    },
  );
});
