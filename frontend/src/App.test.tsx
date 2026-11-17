import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';
import './i18n/config';
import App from './App';
import { apiClient } from './services/Base';
import store from './store';
import { deleteMessage } from './store/notifications/actions';
import { httpError, page, serveApi, signIn } from './test/api';
import {
  author,
  contest,
  jurySubmission,
  submission,
  submissionSet,
} from './test/fixtures';
import type {
  PaginatedResponse,
  Payment,
  ResultsThemeSubmission,
} from './types/api';

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

// Moves the rendered app to another location, as the browser's back and
// forward buttons do, so the current view stays mounted.
function travel(path: string): void {
  act(() => {
    window.history.pushState(null, '', path);
    window.dispatchEvent(new PopStateEvent('popstate'));
  });
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

  it('shows loading, not the previous contest, while another contest loads', async () => {
    let releaseSecond = () => {};
    serveApi({
      'GET /contest/1': () => contest,
      'GET /contest/2': () =>
        new Promise((resolve) => {
          releaseSecond = () =>
            resolve({ ...contest, id: 2, notice_html: '<p>Second notice</p>' });
        }),
    });
    open('/contest/1/details');
    await screen.findByText('Contest instructions');

    travel('/contest/2/details');
    expect(await screen.findByRole('progressbar')).toBeInTheDocument();
    expect(screen.queryByText('Contest instructions')).not.toBeInTheDocument();
    releaseSecond();
    expect(await screen.findByText('Second notice')).toBeInTheDocument();
  });

  it('loads another contest after a failed one', async () => {
    serveApi({
      'GET /contest/1': (config) => {
        throw httpError(config, 404);
      },
      'GET /contest/2': () => ({
        ...contest,
        id: 2,
        notice_html: '<p>Second notice</p>',
      }),
    });
    open('/contest/1/details');
    await screen.findByText('Could not load this contest.');

    travel('/contest/2/details');
    expect(await screen.findByText('Second notice')).toBeInTheDocument();
    expect(
      screen.queryByText('Could not load this contest.'),
    ).not.toBeInTheDocument();
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
        page([
          jurySubmission(11, 'First photograph'),
          jurySubmission(12, 'Second'),
        ]),
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

  it('shows stored payments and reloads them after a change', async () => {
    signIn();
    let paid = true;
    serveApi({
      'GET /contest/1': () => contest,
      'GET /submissionset': () => page([submissionSet]),
      'GET /payment': (): PaginatedResponse<Payment> =>
        page([
          {
            id: 8,
            created: '2026-01-01T00:00:00Z',
            modified: '2026-01-01T00:00:00Z',
            submissionset: submissionSet.id,
            paid,
          },
        ]),
      'POST /payment': (config) => {
        paid = JSON.parse(config.data).paid;
        return {};
      },
    });
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await waitFor(() => expect(screen.getByRole('checkbox')).toBeChecked());

    await user.click(screen.getByRole('checkbox'));
    await waitFor(() => expect(screen.getByRole('checkbox')).not.toBeChecked());
    expect(paid).toBe(false);
  });

  it('requests no payments for an empty list', async () => {
    signIn();
    serveApi({
      'GET /contest/1': () => contest,
      'GET /submissionset': () => page([]),
    });
    open('/admin/contest/1/submissions');
    expect(await screen.findByText('0-0 of 0')).toBeInTheDocument();
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

  it('keeps the table when a payments request for a left page fails', async () => {
    signIn();
    const sets = Array.from({ length: 21 }, (_, index) => ({
      ...submissionSet,
      id: index + 1,
    }));
    let failFirstPage: (() => void) | undefined;
    serveApi({
      'GET /contest/1': () => contest,
      'GET /submissionset': (config) => {
        const pageNumber: number = config.params.page;
        const pageSize: number = config.params.page_size;
        return {
          ...page(
            sets.slice((pageNumber - 1) * pageSize, pageNumber * pageSize),
          ),
          count: sets.length,
        };
      },
      'GET /payment': (config) =>
        config.params.submissionset__in === '21'
          ? page<Payment>([
              {
                id: 8,
                created: '2026-01-01T00:00:00Z',
                modified: '2026-01-01T00:00:00Z',
                submissionset: 21,
                paid: true,
              },
            ])
          : new Promise((_resolve, reject) => {
              failFirstPage = () => reject(httpError(config, 400));
            }),
    });
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await waitFor(() => expect(failFirstPage).toBeDefined());

    await user.click(screen.getByRole('button', { name: 'Go to next page' }));
    expect(await screen.findByText('21-21 of 21')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('checkbox')).toBeChecked());
    await act(async () => failFirstPage?.());
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByText('21-21 of 21')).toBeInTheDocument();
    expect(screen.getByRole('checkbox')).toBeChecked();
    expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(1);
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
        throw httpError(config, 503);
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
      await screen.findByText('Request failed. Please try again.'),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(
        within(screen.getByRole('row', { name: /Ana Novak/ }))
          .getAllByRole('cell')
          .map((cell) => cell.textContent),
      ).toEqual([contest.title, 'Ana Novak', '1', '1', 'EditDelete']),
    );
  });

  it('explains a delete refused because the contest closed', async () => {
    signIn();
    let activeContests = [contest];
    serveApi({
      'GET /contest': () => page(activeContests),
      'GET /submission': () => page([submission(11, 'First')]),
      'DELETE /submission/11': (config) => {
        // The contest closed after the list loaded, so the reload no longer
        // lists it.
        activeContests = [];
        throw httpError(config, 403, {
          detail: 'This contest is not accepting entries.',
        });
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
      await screen.findByText("You don't have any active submission to edit."),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        'This contest has closed, so its submissions can no longer be deleted.',
      ),
    ).toBeInTheDocument();
  });

  it('lists one row per author in the order the authors were created', async () => {
    signIn();
    const [nature] = contest.themes;
    if (!nature) {
      throw new Error('The contest fixture has no theme');
    }
    const twoThemes = {
      ...contest,
      themes: [nature, { ...nature, id: 3, title: 'City' }],
    };
    const mia = { ...author, id: 9, first_name: 'Mia', last_name: 'Zupan' };
    serveApi({
      'GET /contest': () => page([twoThemes]),
      'GET /submission': () =>
        page([
          { ...submission(11, 'Forest'), author: mia },
          submission(12, 'River'),
          { ...submission(13, 'Street'), author: mia, theme: 3 },
          { ...submission(14, 'Bridge'), author: mia, theme: 3 },
        ]),
    });
    open('/user/submissions');
    await screen.findByRole('row', { name: /Mia Zupan/ });
    expect(
      screen
        .getAllByRole('row')
        .slice(1)
        .map((row) =>
          within(row)
            .getAllByRole('cell')
            .map((cell) => cell.textContent),
        ),
    ).toEqual([
      [contest.title, 'Ana Novak', '1', '1', 'EditDelete'],
      [contest.title, 'Mia Zupan', '2', '3', 'EditDelete'],
    ]);
  });
});

describe('theme results', () => {
  function result(
    id: number,
    title: string,
    authorId: number,
    [first_name, last_name]: [string, string],
  ): ResultsThemeSubmission {
    return {
      id,
      created: '2026-01-01T00:00:00Z',
      modified: '2026-01-01T00:00:00Z',
      author: {
        ...author,
        id: authorId,
        first_name,
        last_name,
        reward: null,
        reward_theme: null,
        country: 'SI',
      },
      theme: 2,
      title,
      files: null,
      accepted: false,
      reward_kind: null,
      reward_label: null,
    };
  }

  function openWithAuthorReward(rewardTheme: number): void {
    const [nature] = contest.themes;
    if (!nature) {
      throw new Error('The contest fixture has no theme');
    }
    const hills = result(21, 'Hills', 3, ['Ana', 'Zupan']);
    serveApi({
      'GET /contest/1': () => contest,
      'GET /results/theme/2': () => ({
        ...nature,
        submissions: [
          {
            ...hills,
            author: {
              ...hills.author,
              reward: 'Best young author',
              reward_theme: rewardTheme,
            },
          },
        ],
      }),
    });
    open('/results/contest/1/theme/2');
  }

  it('shows an author reward in the theme it was given for', async () => {
    openWithAuthorReward(2);
    await screen.findByText('Hills');
    expect(screen.getByText('Best young author')).toBeInTheDocument();
  });

  it('hides an author reward given for another theme', async () => {
    openWithAuthorReward(3);
    await screen.findByText('Hills');
    expect(screen.queryByText('Best young author')).not.toBeInTheDocument();
  });

  const rewardHighlight = { backgroundColor: 'rgb(254, 225, 1, 0.5)' };

  function authorCells(): HTMLElement[] {
    return within(
      screen.getByRole('row', { name: /^Zupan, Ana/ }),
    ).getAllByRole('cell');
  }

  it('highlights an author rewarded in this theme', async () => {
    openWithAuthorReward(2);
    await screen.findByText('Hills');
    for (const cell of authorCells()) {
      expect(cell).toHaveStyle(rewardHighlight);
    }
  });

  it('does not highlight an author rewarded in another theme', async () => {
    openWithAuthorReward(3);
    await screen.findByText('Hills');
    for (const cell of authorCells()) {
      expect(cell).not.toHaveStyle(rewardHighlight);
    }
  });

  it('groups results by author, sorted by last and first name', async () => {
    const [nature] = contest.themes;
    if (!nature) {
      throw new Error('The contest fixture has no theme');
    }
    serveApi({
      'GET /contest/1': () => contest,
      'GET /results/theme/2': () => ({
        ...nature,
        submissions: [
          result(21, 'Hills', 3, ['Ana', 'Zupan']),
          result(22, 'Lake', 7, ['Mia', 'Novak']),
          result(23, 'Fog', 3, ['Ana', 'Zupan']),
          result(24, 'Snow', 9, ['Ana', 'Novak']),
          result(25, 'Rain', 7, ['Mia', 'Novak']),
        ],
      }),
    });
    open('/results/contest/1/theme/2');
    await screen.findByText('Hills');
    expect(screen.getAllByRole('row').map((row) => row.textContent)).toEqual([
      'Novak, Ana (SI)',
      'Snow',
      'Novak, Mia (SI)',
      'Lake',
      'Rain',
      'Zupan, Ana (SI)',
      'Hills',
      'Fog',
    ]);
  });

  it('sorts author names by Slovenian collation', async () => {
    const [nature] = contest.themes;
    if (!nature) {
      throw new Error('The contest fixture has no theme');
    }
    serveApi({
      'GET /contest/1': () => contest,
      'GET /results/theme/2': () => ({
        ...nature,
        submissions: [
          result(31, 'Bridge', 1, ['Žan', 'Žagar']),
          result(32, 'Field', 2, ['Ana', 'Zupan']),
          result(33, 'Forest', 3, ['Dana', 'Novak']),
          result(34, 'River', 4, ['Ema', 'Šuštar']),
          result(35, 'Sea', 5, ['Ana', 'Sever']),
          result(36, 'Street', 6, ['Črt', 'Novak']),
          result(37, 'Tower', 7, ['Iva', 'Čeh']),
          result(38, 'Valley', 8, ['Tine', 'Cerar']),
        ],
      }),
    });
    open('/results/contest/1/theme/2');
    await screen.findByText('Bridge');
    expect(
      screen
        .getAllByRole('row')
        .map((row) => row.textContent)
        .filter((text) => text.endsWith('(SI)')),
    ).toEqual([
      'Cerar, Tine (SI)',
      'Čeh, Iva (SI)',
      'Novak, Črt (SI)',
      'Novak, Dana (SI)',
      'Sever, Ana (SI)',
      'Šuštar, Ema (SI)',
      'Zupan, Ana (SI)',
      'Žagar, Žan (SI)',
    ]);
  });
});
