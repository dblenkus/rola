import { screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import './i18n/config';
import store from './store';
import { deleteMessage } from '../features/notifications/state/actions';
import { httpError, page, serveApi, signIn } from '../test/api';
import { open, travel } from '../test/app';
import { contest, submission } from '../test/fixtures';

beforeEach(() => {
  localStorage.clear();
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
});

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
