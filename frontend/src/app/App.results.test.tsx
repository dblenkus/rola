import { screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import './i18n/config';
import store from './store';
import { deleteMessage } from '../features/notifications/state/actions';
import { serveApi } from '../test/api';
import { open } from '../test/app';
import { author, contest } from '../test/fixtures';
import type { ResultsThemeSubmission } from '../shared/api/types';

beforeEach(() => {
  localStorage.clear();
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
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
      'GET /contests/1': () => contest,
      'GET /results/themes/2': () => ({
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

  function authorAwardMarks(): HTMLElement[] {
    return Array.from(
      screen
        .getByRole('row', { name: /^Zupan, Ana/ })
        .querySelectorAll<HTMLElement>('.rl-award'),
    );
  }

  it('highlights an author rewarded in this theme', async () => {
    openWithAuthorReward(2);
    await screen.findByText('Hills');
    const marks = authorAwardMarks();
    expect(marks).toHaveLength(1);
    expect(marks[0]).toHaveTextContent('Best young author');
  });

  it('does not highlight an author rewarded in another theme', async () => {
    openWithAuthorReward(3);
    await screen.findByText('Hills');
    expect(authorAwardMarks()).toHaveLength(0);
  });

  it('groups results by author, sorted by last and first name', async () => {
    const [nature] = contest.themes;
    if (!nature) {
      throw new Error('The contest fixture has no theme');
    }
    serveApi({
      'GET /contests/1': () => contest,
      'GET /results/themes/2': () => ({
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
      'GET /contests/1': () => contest,
      'GET /results/themes/2': () => ({
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
