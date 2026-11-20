// Harness for the RateSubmission tests: a fake judging API with the judge's
// ratings as server state, rendering, and queries by role and name. The name
// does not match the Vitest include pattern, so it runs no tests itself.
import { act, render, screen, within } from '@testing-library/react';
import type { InternalAxiosRequestConfig } from 'axios';
import type { ReactNode } from 'react';
import { Provider } from 'react-redux';
import { createMemoryRouter, RouterProvider } from 'react-router';
import type { AppStore } from '../../../app/store';
import { httpError, page, serveApi, withStatus } from '../../../test/api';
import { contest as defaultContest, rating } from '../../../test/fixtures';
import type {
  Contest,
  JurySubmission,
  Rating,
} from '../../../shared/api/types';
import RateSubmission from './RateSubmission';

export const scores = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

// Ids the fake API gives to new ratings, in order.
const firstNewRatingId = 901;
const lastNewRatingId = 999;

interface JudgingOptions {
  contest?: Contest;
  submissions: JurySubmission[];
  // The judge's ratings stored before the test.
  ratings?: Rating[];
}

export interface JudgingApi {
  // Each score sent with POST /rating, in order.
  saves: { submission: number; rating: number }[];
  // Each rating id sent with DELETE /rating/{id}, in order.
  deletes: number[];
  // While true, writes wait until `release` answers them.
  holdWrites: boolean;
  // Answers the oldest held write.
  release: () => void;
  heldWrites: () => number;
  // The status writes fail with, or null for success.
  writeStatus: number | null;
  // The status the theme-wide GET /rating fails with, or null for success.
  themeRatingsStatus: number | null;
  // Submissions whose own GET /rating fails.
  failingSubmissionRatings: Set<number>;
  // Every request other than a GET, as "METHOD /path".
  writes: () => string[];
}

function isScore(
  data: unknown,
): data is { submission: number; rating: number } {
  return (
    typeof data === 'object' &&
    data !== null &&
    'submission' in data &&
    typeof data.submission === 'number' &&
    'rating' in data &&
    typeof data.rating === 'number'
  );
}

// Serves the contest, the theme's submissions and the judge's ratings. A
// score replaces the submission's rating under the same id, as the server's
// update_or_create does, or stores a new one under the next new id.
export function serveJudging({
  contest = defaultContest,
  submissions,
  ratings = [],
}: JudgingOptions): JudgingApi {
  const stored = new Map<number, Rating>(
    ratings.map((stored) => [stored.submission, stored]),
  );
  let nextId = firstNewRatingId;
  const held: (() => void)[] = [];

  const answer = <T,>(respond: () => T): T | Promise<T> => {
    if (!api.holdWrites) return respond();
    return new Promise<T>((resolve, reject) =>
      held.push(() => {
        try {
          resolve(respond());
        } catch (error) {
          reject(error);
        }
      }),
    );
  };

  const deleteRating = (id: number) => (config: InternalAxiosRequestConfig) => {
    api.deletes.push(id);
    return answer(() => {
      if (api.writeStatus !== null) throw httpError(config, api.writeStatus);
      const found = [...stored.values()].find((saved) => saved.id === id);
      if (!found) throw httpError(config, 404);
      stored.delete(found.submission);
      return withStatus(204, '');
    });
  };
  const ratingIds = [
    ...ratings.map((stored) => stored.id),
    ...Array.from(
      { length: lastNewRatingId - firstNewRatingId + 1 },
      (_, index) => firstNewRatingId + index,
    ),
  ];

  const adapter = serveApi({
    [`GET /contest/${contest.id}`]: () => contest,
    'GET /judge/submission': () => page(submissions),
    'GET /rating': (config, url) => {
      if (url.searchParams.has('theme')) {
        if (api.themeRatingsStatus !== null)
          throw httpError(config, api.themeRatingsStatus);
        return page([...stored.values()]);
      }
      const submissionId = Number(url.searchParams.get('submission'));
      if (api.failingSubmissionRatings.has(submissionId))
        throw httpError(config, 503);
      const found = stored.get(submissionId);
      return page(found ? [found] : []);
    },
    'POST /rating': (config) => {
      const data: unknown = JSON.parse(String(config.data));
      if (!isScore(data)) throw new Error(`Unexpected score: ${config.data}`);
      api.saves.push(data);
      return answer(() => {
        if (api.writeStatus !== null) throw httpError(config, api.writeStatus);
        const previous = stored.get(data.submission);
        const saved = rating(
          previous?.id ?? nextId++,
          data.submission,
          data.rating,
        );
        stored.set(data.submission, saved);
        return saved;
      });
    },
    ...Object.fromEntries(
      ratingIds.map((id) => [`DELETE /rating/${id}`, deleteRating(id)]),
    ),
  });

  const api: JudgingApi = {
    saves: [],
    deletes: [],
    holdWrites: false,
    release: () => {
      const next = held.shift();
      if (!next) throw new Error('No write is held');
      next();
    },
    heldWrites: () => held.length,
    writeStatus: null,
    themeRatingsStatus: null,
    failingSubmissionRatings: new Set(),
    writes: () =>
      adapter.mock.calls
        .map(([config]) => config)
        .filter((config) => config.method !== 'get')
        .map((config) => `${config.method?.toUpperCase()} ${config.url}`),
  };
  return api;
}

interface RenderOptions {
  path?: string;
  // Rendered before the rater on its route, such as a text field.
  beside?: ReactNode;
  // The theme page that "Back to theme" leads to.
  themePage?: ReactNode;
}

export function renderRater(
  store: AppStore,
  {
    path = '/judge/contest/1/theme/2/rate?submission=11',
    beside,
    themePage = <p>Theme overview</p>,
  }: RenderOptions = {},
) {
  const router = createMemoryRouter(
    [
      {
        path: '/judge/contest/:contestId/theme/:themeId/rate',
        element: (
          <>
            {beside}
            <RateSubmission />
          </>
        ),
      },
      {
        path: '/judge/contest/:contestId/theme/:themeId',
        element: themePage,
      },
    ],
    { initialEntries: [path] },
  );
  render(
    <Provider store={store}>
      <RouterProvider router={router} />
    </Provider>,
  );
  return router;
}

// A response settles through promise callbacks only, so one macrotask later
// it has reached the view, whether the view uses it or not.
export async function settle() {
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
}

export function scoreGroup(): HTMLElement {
  return screen.getByRole('group', { name: 'Score from 1 to 10' });
}

export function scoreKey(value: number): HTMLElement {
  return within(scoreGroup()).getByRole('button', { name: String(value) });
}

// The score on the pressed key, or 0 when no key is pressed.
export function pressedScore(): number {
  const pressed = scores.filter(
    (value) => scoreKey(value).getAttribute('aria-pressed') === 'true',
  );
  if (pressed.length > 1) {
    throw new Error(`Several score keys are pressed: ${pressed.join(', ')}`);
  }
  return pressed[0] ?? 0;
}

export function photoScore(): HTMLElement {
  return screen.getByRole('region', { name: 'Photo score' });
}

const normalized = (text: string | null): string =>
  (text ?? '').replace(/\s+/g, ' ').trim();

// The text of the announcement region.
export function announcement(): string {
  return normalized(screen.getByRole('status').textContent);
}

// Matches the innermost element whose whole text is `text`, however the text
// is split into elements inside it.
export function exactText(text: string) {
  return (_content: string, element: Element | null): boolean =>
    element !== null &&
    normalized(element.textContent) === text &&
    ![...element.children].some(
      (child) => normalized(child.textContent) === text,
    );
}
