import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';
import './i18n/config';
import App from './App';
import { apiClient } from './services/Base';
import store from './store';
import { deleteMessage } from './store/notifications/actions';
import { httpError, page, serveApi, signIn } from './test/api';
import { contest, submission, submissionSet } from './test/fixtures';

beforeEach(() => {
  localStorage.clear();
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
});

function open(path: string): void {
  window.history.replaceState(null, '', path);
  render(<App />);
}

describe('contest pages', () => {
  it('lists every page of active contests', async () => {
    serveApi({
      'GET /contest': (_config, url) =>
        url.searchParams.get('page') === '2'
          ? page([{ ...contest, id: 3, title: 'Winter photographs' }])
          : {
              ...page([contest]),
              next: '/api/v1/contest?is_active=true&page=2',
            },
    });
    open('/contests');
    expect(
      await screen.findByRole('heading', { name: 'Winter photographs' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: contest.title }),
    ).toBeInTheDocument();
  });

  it('shows that no contest is active', async () => {
    serveApi({ 'GET /contest': () => page([]) });
    open('/contests');
    expect(await screen.findByText('No active contests.')).toBeInTheDocument();
  });

  it('shows a failed contest list', async () => {
    serveApi({
      'GET /contest': (config) => {
        throw httpError(config, 503);
      },
    });
    open('/contests');
    expect(
      await screen.findByText('Could not load contests. Please try again.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });

  it('shows the contest notice', async () => {
    serveApi({ 'GET /contest/1': () => contest });
    open('/contest/1/details');
    expect(await screen.findByText('Contest instructions')).toBeInTheDocument();
  });

  it('shows a failed contest', async () => {
    serveApi({
      'GET /contest/1': (config) => {
        throw httpError(config, 404);
      },
    });
    open('/contest/1/details');
    expect(
      await screen.findByText('Could not load this contest.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });

  it('counts submissions from every page in the edit list', async () => {
    signIn();
    serveApi({
      'GET /contest': () => page([contest]),
      'GET /submission': (_config, url) =>
        url.searchParams.get('page') === '2'
          ? page([submission(12, 'Second')])
          : {
              ...page([submission(11, 'First')]),
              next: '/api/v1/submission?contest=1&page=2',
            },
    });
    open('/user/submissions');
    const row = await screen.findByRole('row', { name: /Ana Novak/ });
    expect(
      within(row)
        .getAllByRole('cell')
        .map((cell) => cell.textContent),
    ).toEqual([contest.title, 'Ana Novak', '1', '2', 'EditDelete']);
  });
});

describe('failed page requests', () => {
  it.each([
    '/contest/1/upload',
    '/contest/1/confirm',
    '/user/submissions',
    '/judge',
    '/judge/contest/1/theme/2',
    '/judge/contest/1/theme/2/rate',
    '/judge/contest/1/theme/2/overview',
    '/admin/contest/1/submissions',
    '/admin/contest/1/submission/5',
    '/results/contest/1',
    '/results/contest/1/theme/2',
    '/results/contest/1/theme/2/submission/11',
  ])('shows a permission error instead of loading at %s', async (path) => {
    signIn();
    apiClient.defaults.adapter = async (config) => {
      throw httpError(config, 403, { detail: 'Forbidden' });
    };
    open(path);
    expect(
      await screen.findByText(
        'You do not have permission to perform this action.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });

  it('shows a failed submission list after the contest loads', async () => {
    signIn();
    serveApi({
      'GET /contest/1': () => contest,
      'GET /submissionset': (config) => {
        throw httpError(config, 403);
      },
    });
    open('/admin/contest/1/submissions');
    expect(
      await screen.findByText(
        'You do not have permission to perform this action.',
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: contest.title }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });
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

  it('returns to the full requested location after login', async () => {
    serveApi({
      'POST /user/login': () => ({
        token: 'signed-in',
        expires: '2999-01-01T00:00:00Z',
      }),
      'GET /contest/1': () => contest,
      'GET /judge/submission': () =>
        page([submission(11, 'First photograph'), submission(12, 'Second')]),
      'GET /rating': () => page([]),
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
      'POST /user/activate_account': (config) => {
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
      'POST /user/activate_account': (config) => {
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
      'POST /user/request_password_reset': (config) => {
        attempts += 1;
        if (attempts === 1) {
          throw httpError(config, 429, { detail: 'Request was throttled.' });
        }
        return {};
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

describe('admin submission list', () => {
  it('reloads the list after a confirmed delete only', async () => {
    signIn();
    const adapter = serveApi({
      'GET /contest/1': () => contest,
      'GET /submissionset': () => page([submissionSet]),
      'GET /payment': () => page([]),
      'DELETE /submissionset/5': () => null,
    });
    const listRequests = () =>
      adapter.mock.calls.filter(
        ([config]) =>
          config.method === 'get' && config.url === '/submissionset',
      ).length;
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'No',
      }),
    );
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    );
    expect(listRequests()).toBe(1);

    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'Yes',
      }),
    );
    await waitFor(() => expect(listRequests()).toBe(2));
    expect(
      adapter.mock.calls.filter(([config]) => config.method === 'delete'),
    ).toHaveLength(1);
  });

  it('shows the previous page after deleting the last row of a page', async () => {
    signIn();
    let sets = Array.from({ length: 21 }, (_, index) => ({
      ...submissionSet,
      id: index + 1,
    }));
    serveApi({
      'GET /contest/1': () => contest,
      // Like the API, answers a page past the end with 404.
      'GET /submissionset': (config) => {
        const pageNumber: number = config.params.page;
        const pageSize: number = config.params.page_size;
        const results = sets.slice(
          (pageNumber - 1) * pageSize,
          pageNumber * pageSize,
        );
        if (pageNumber > 1 && !results.length) {
          throw httpError(config, 404, { detail: 'Invalid page.' });
        }
        return { ...page(results), count: sets.length };
      },
      'GET /payment': () => page([]),
      'DELETE /submissionset/21': () => {
        sets = sets.slice(0, 20);
        return null;
      },
    });
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await user.click(
      await screen.findByRole('button', { name: 'Go to next page' }),
    );
    expect(await screen.findByText('21-21 of 21')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'Yes',
      }),
    );
    expect(await screen.findByText('1-20 of 20')).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    );
    expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(20);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('keeps the table after a failed payment update', async () => {
    signIn();
    let attempts = 0;
    serveApi({
      'GET /contest/1': () => contest,
      'GET /submissionset': () => page([submissionSet]),
      'GET /payment': () => page([]),
      'POST /payment': (config) => {
        attempts += 1;
        if (attempts === 1) {
          throw httpError(config, 400);
        }
        return {};
      },
    });
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await user.click(await screen.findByRole('checkbox'));
    expect(
      await screen.findByText('Request failed. Please try again.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();

    await user.click(screen.getByRole('checkbox'));
    await waitFor(() =>
      expect(
        screen.queryByText('Request failed. Please try again.'),
      ).not.toBeInTheDocument(),
    );
    expect(attempts).toBe(2);
  });

  it('keeps the table after a failed delete', async () => {
    signIn();
    serveApi({
      'GET /contest/1': () => contest,
      'GET /submissionset': () => page([submissionSet]),
      'GET /payment': () => page([]),
      'DELETE /submissionset/5': (config) => {
        throw httpError(config, 403, { detail: 'Forbidden' });
      },
    });
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'Yes',
      }),
    );
    expect(
      await screen.findByText(
        'You do not have permission to perform this action.',
      ),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
  });
});

describe('submissions edit list', () => {
  it('shows what is left after a failed delete', async () => {
    signIn();
    let submissions = [submission(11, 'First'), submission(12, 'Second')];
    serveApi({
      'GET /contest': () => page([contest]),
      'GET /submission': () => page(submissions),
      'DELETE /submission/11': () => {
        submissions = submissions.filter(({ id }) => id !== 11);
        return null;
      },
      'DELETE /submission/12': (config) => {
        throw httpError(config, 403, { detail: 'Forbidden' });
      },
    });
    const user = userEvent.setup();
    open('/user/submissions');
    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'Yes',
      }),
    );
    expect(
      await screen.findByText(
        'You do not have permission to perform this action.',
      ),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(
        within(screen.getByRole('row', { name: /Ana Novak/ }))
          .getAllByRole('cell')
          .map((cell) => cell.textContent),
      ).toEqual([contest.title, 'Ana Novak', '1', '1', 'EditDelete']),
    );
  });
});
