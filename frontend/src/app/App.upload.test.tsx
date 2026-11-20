import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';
import './i18n/config';
import store from './store';
import { deleteMessage } from '../features/notifications/state/actions';
import { httpError, page, serveApi, signIn, withStatus } from '../test/api';
import { open } from '../test/app';
import { author, contest, submission } from '../test/fixtures';

beforeEach(() => {
  localStorage.clear();
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
});

describe('submissions edit list', () => {
  it('shows what is left after a failed delete', async () => {
    signIn();
    let submissions = [submission(11, 'First'), submission(12, 'Second')];
    serveApi({
      'GET /contests': () => page([contest]),
      'GET /submissions': () => page(submissions),
      'DELETE /submissions/11': () => {
        submissions = submissions.filter(({ id }) => id !== 11);
        return withStatus(204, null);
      },
      'DELETE /submissions/12': (config) => {
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
      'GET /contests': () => page(activeContests),
      'GET /submissions': () => page([submission(11, 'First')]),
      'DELETE /submissions/11': (config) => {
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
      'GET /contests': () => page([twoThemes]),
      'GET /submissions': () =>
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

  it('reloads the list for another account that signs in from another tab', async () => {
    signIn();
    const mia = { ...author, id: 9, first_name: 'Mia', last_name: 'Zupan' };
    const adapter = serveApi({
      'GET /contests': () => page([contest]),
      'GET /submissions': (config) =>
        config.headers.get('Authorization') === 'Bearer next-account'
          ? page([{ ...submission(12, 'River'), author: mia }])
          : page([submission(11, 'Forest')]),
    });
    open('/user/submissions');
    await screen.findByRole('row', { name: /Ana Novak/ });
    act(() => {
      signIn('next-account', 'next@example.com');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token' }));
    });
    expect(
      screen.queryByRole('row', { name: /Ana Novak/ }),
    ).not.toBeInTheDocument();
    expect(
      await screen.findByRole('row', { name: /Mia Zupan/ }),
    ).toBeInTheDocument();
    expect(
      adapter.mock.calls
        .map(([config]) => config)
        .filter((config) => config.url === '/submissions')
        .map((config) => config.headers.get('Authorization')),
    ).toEqual(['Bearer signed-in', 'Bearer next-account']);
  });
});
