import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Provider } from 'react-redux';
import {
  createMemoryRouter,
  MemoryRouter,
  Route,
  RouterProvider,
  Routes,
} from 'react-router';
import { beforeEach, expect, it } from 'vitest';
import '../../i18n/config';
import { createAppStore, type AppStore } from '../../store';
import { httpError, page, serveApi } from '../../test/api';
import { contest, jurySubmission } from '../../test/fixtures';
import type {
  JurySubmission,
  PaginatedResponse,
  Rating,
} from '../../types/api';
import RateSubmission from './RateSubmission';

interface PendingRating {
  submission: number;
  resolve: (data: PaginatedResponse<Rating>) => void;
}

const pending: PendingRating[] = [];
let store: AppStore;

beforeEach(() => {
  pending.length = 0;
  store = createAppStore();
});

function ratings(submissionId: number, value: number) {
  return page([
    {
      id: submissionId,
      created: '2026-01-01T00:00:00Z',
      modified: '2026-01-01T00:00:00Z',
      submission: submissionId,
      rating: value,
    },
  ]);
}

// A response settles through promise callbacks only, so one macrotask later
// it has reached the view, whether the view uses it or not.
async function settle() {
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
}

async function answerRating(submissionId: number, value: number) {
  await waitFor(() =>
    expect(pending.map((request) => request.submission)).toContain(
      submissionId,
    ),
  );
  const index = pending.findIndex(
    (request) => request.submission === submissionId,
  );
  const [request] = pending.splice(index, 1);
  request?.resolve(ratings(submissionId, value));
  await settle();
}

function renderRater(path = '/judge/contest/1/theme/2/rate?submission=11') {
  render(
    <Provider store={store}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/judge/contest/:contestId/theme/:themeId/rate"
            element={<RateSubmission />}
          />
        </Routes>
      </MemoryRouter>
    </Provider>,
  );
}

function filledStars(): number {
  return screen
    .getAllByTestId('StarIcon')
    .filter((star) => getComputedStyle(star).color === 'rgb(255, 180, 0)')
    .length;
}

function star(value: number): HTMLElement {
  const icon = screen.getAllByTestId('StarIcon')[value - 1];
  if (!icon) throw new Error(`No star for rating ${value}`);
  return icon;
}

it('keeps the rater after a failed rating load', async () => {
  let unavailable = true;
  const saves: unknown[] = [];
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () =>
      page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
    'GET /rating': (config) => {
      if (config.params.submission !== 12) return page([]);
      if (unavailable) {
        throw httpError(config, 503);
      }
      return ratings(12, 4);
    },
    'POST /rating': (config) => {
      saves.push(JSON.parse(String(config.data)));
      return {};
    },
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('{ArrowRight}');
  expect(
    await screen.findByText('Request failed. Please try again.'),
  ).toBeInTheDocument();
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  await user.keyboard('6');
  await waitFor(() => expect(filledStars()).toBe(6));
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
  expect(saves).toEqual([{ submission: 12, rating: 6 }]);

  unavailable = false;
  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await waitFor(() => expect(filledStars()).toBe(4));
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
});

it('ignores rating keys when the theme does not load', async () => {
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () => page([jurySubmission(11, 'First')]),
    'GET /rating': () => page([]),
  });
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  cleanup();

  const saves: unknown[] = [];
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': (config) => {
      throw httpError(config, 503);
    },
    'GET /rating': () => page([]),
    'POST /rating': (config) => {
      saves.push(JSON.parse(String(config.data)));
      return {};
    },
  });
  const user = userEvent.setup();
  renderRater();
  expect(
    await screen.findByText('Request failed. Please try again.'),
  ).toBeInTheDocument();
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
  await user.keyboard('7');
  await settle();
  expect(saves).toEqual([]);
});

it('shows each submission its own rating while the judge moves on', async () => {
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () =>
      page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
    'GET /rating': ({ params }) =>
      new Promise((resolve) =>
        pending.push({ submission: params.submission, resolve }),
      ),
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await answerRating(12, 5);
  expect(filledStars()).toBe(5);
  await answerRating(11, 7);
  expect(filledStars()).toBe(5);

  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  expect(filledStars()).toBe(0);
  await answerRating(11, 7);
  expect(filledStars()).toBe(7);
});

it('stays on the shown submission when an earlier save finishes', async () => {
  const saves: (() => void)[] = [];
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () =>
      page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
    'GET /rating': ({ params }) =>
      params.submission === 12 ? ratings(12, 3) : page([]),
    'POST /rating': () =>
      new Promise((resolve) => saves.push(() => resolve({}))),
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('5');
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await waitFor(() => expect(filledStars()).toBe(3));
  expect(saves).toHaveLength(1);
  saves[0]?.();
  await settle();
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(filledStars()).toBe(3);
});

it('keeps the next rater on its submission when a closed rater saves late', async () => {
  const saves: (() => void)[] = [];
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () =>
      page([
        jurySubmission(11, 'First'),
        jurySubmission(12, 'Second'),
        jurySubmission(13, 'Third'),
      ]),
    'GET /rating': () => page([]),
    'POST /rating': () =>
      new Promise((resolve) => saves.push(() => resolve({}))),
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await user.keyboard('5');
  await waitFor(() => expect(saves).toHaveLength(1));
  cleanup();

  renderRater('/judge/contest/1/theme/2/rate?submission=12');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  saves[0]?.();
  await settle();
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  expect(screen.queryByRole('img', { name: 'Third' })).not.toBeInTheDocument();
});

it('ignores new ratings while a rating save is pending', async () => {
  const saves: unknown[] = [];
  const answers: (() => void)[] = [];
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () =>
      page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
    'GET /rating': () => page([]),
    'POST /rating': (config) => {
      saves.push(JSON.parse(String(config.data)));
      return new Promise((resolve) => answers.push(() => resolve({})));
    },
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('5');
  await waitFor(() => expect(saves).toHaveLength(1));
  await user.keyboard('7');
  await user.click(star(7));
  await settle();
  expect(saves).toEqual([{ submission: 11, rating: 5 }]);
  expect(filledStars()).toBe(0);

  answers[0]?.();
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await user.keyboard('7');
  await waitFor(() => expect(saves).toHaveLength(2));
  expect(saves).toEqual([
    { submission: 11, rating: 5 },
    { submission: 12, rating: 7 },
  ]);
});

it('ignores auto-repeated digit keys but not arrow keys', async () => {
  const saves: unknown[] = [];
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () =>
      page([
        jurySubmission(11, 'First'),
        jurySubmission(12, 'Second'),
        jurySubmission(13, 'Third'),
      ]),
    'GET /rating': () => page([]),
    'POST /rating': (config) => {
      saves.push(JSON.parse(String(config.data)));
      return {};
    },
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('7');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  // fireEvent dispatches at once; the rater listens for keys on the shown
  // submission only after its effects have run.
  await settle();
  fireEvent.keyDown(window, { key: '7', repeat: true });
  await settle();
  expect(saves).toEqual([{ submission: 11, rating: 7 }]);
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();

  fireEvent.keyDown(window, { key: 'ArrowRight', repeat: true });
  expect(await screen.findByRole('img', { name: 'Third' })).toBeVisible();
});

it('keeps the rater after a failed save', async () => {
  let attempts = 0;
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () =>
      page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
    'GET /rating': () => page([]),
    'POST /rating': (config) => {
      attempts += 1;
      if (attempts === 1) {
        throw httpError(config, 400);
      }
      return {};
    },
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('5');
  expect(
    await screen.findByText('Request failed. Please try again.'),
  ).toBeInTheDocument();
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();

  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await user.keyboard('5');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  expect(attempts).toBe(2);
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
});

const twoThemes = {
  ...contest,
  themes: [...contest.themes, { ...contest.themes[0]!, id: 3, title: 'City' }],
};

it('shows nothing from the previous theme while another theme loads', async () => {
  serveApi({
    'GET /contest/1': () => twoThemes,
    'GET /judge/submission': () => page([jurySubmission(11, 'First')]),
    'GET /rating': () => page([]),
  });
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  cleanup();

  const saves: unknown[] = [];
  const ratingLoads: unknown[] = [];
  let answer: (data: PaginatedResponse<JurySubmission>) => void = () => {};
  serveApi({
    'GET /contest/1': () => twoThemes,
    'GET /judge/submission': () =>
      new Promise((resolve) => {
        answer = resolve;
      }),
    'GET /rating': ({ params }) => {
      ratingLoads.push(params.submission);
      return page([]);
    },
    'POST /rating': (config) => {
      saves.push(JSON.parse(String(config.data)));
      return {};
    },
  });
  const user = userEvent.setup();
  renderRater('/judge/contest/1/theme/3/rate');
  expect(await screen.findByRole('progressbar')).toBeInTheDocument();
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
  await user.keyboard('7');
  await settle();
  expect(saves).toEqual([]);
  expect(ratingLoads).toEqual([]);

  answer(page([jurySubmission(21, 'Street')]));
  expect(await screen.findByRole('img', { name: 'Street' })).toBeVisible();
  // The rating is requested by an effect after the photograph renders.
  await waitFor(() => expect(ratingLoads).toEqual([21]));
});

it('keeps the latest theme when an earlier load finishes last', async () => {
  const answers = new Map<
    string,
    (data: PaginatedResponse<JurySubmission>) => void
  >();
  serveApi({
    'GET /contest/1': () => twoThemes,
    'GET /judge/submission': ({ params }) =>
      new Promise((resolve) => answers.set(String(params.theme), resolve)),
    'GET /rating': () => page([]),
  });
  renderRater('/judge/contest/1/theme/2/rate');
  await waitFor(() => expect(answers.has('2')).toBe(true));
  cleanup();
  renderRater('/judge/contest/1/theme/3/rate');
  await waitFor(() => expect(answers.has('3')).toBe(true));

  answers.get('3')?.(page([jurySubmission(21, 'Street')]));
  expect(await screen.findByRole('img', { name: 'Street' })).toBeVisible();
  answers.get('2')?.(page([jurySubmission(11, 'First')]));
  await settle();
  expect(screen.getByRole('img', { name: 'Street' })).toBeVisible();
  expect(screen.queryByRole('img', { name: 'First' })).not.toBeInTheDocument();
});

it('shows no error from a theme load the judge has left', async () => {
  let failFirstTheme: (() => void) | undefined;
  serveApi({
    'GET /contest/1': () => twoThemes,
    'GET /judge/submission': (config) =>
      config.params.theme === 2
        ? new Promise((_resolve, reject) => {
            failFirstTheme = () => reject(httpError(config, 503));
          })
        : page([jurySubmission(21, 'Street')]),
    'GET /rating': () => page([]),
  });
  const router = createMemoryRouter(
    [
      {
        path: '/judge/contest/:contestId/theme/:themeId/rate',
        element: <RateSubmission />,
      },
    ],
    { initialEntries: ['/judge/contest/1/theme/2/rate'] },
  );
  render(
    <Provider store={store}>
      <RouterProvider router={router} />
    </Provider>,
  );
  await waitFor(() => expect(failFirstTheme).toBeDefined());

  // The same rater stays mounted, as after a jump in the browser history.
  await act(() => router.navigate('/judge/contest/1/theme/3/rate'));
  expect(await screen.findByRole('img', { name: 'Street' })).toBeVisible();
  failFirstTheme?.();
  await settle();
  expect(screen.getByRole('img', { name: 'Street' })).toBeVisible();
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
});

it('leaves the error of a failed theme behind when another theme opens', async () => {
  serveApi({
    'GET /contest/1': () => twoThemes,
    'GET /judge/submission': (config) => {
      if (config.params.theme === 2) throw httpError(config, 503);
      return page([jurySubmission(21, 'Street'), jurySubmission(22, 'Bridge')]);
    },
    'GET /rating': () => page([]),
  });
  const router = createMemoryRouter(
    [
      {
        path: '/judge/contest/:contestId/theme/:themeId/rate',
        element: <RateSubmission />,
      },
    ],
    { initialEntries: ['/judge/contest/1/theme/2/rate'] },
  );
  render(
    <Provider store={store}>
      <RouterProvider router={router} />
    </Provider>,
  );
  expect(
    await screen.findByText('Request failed. Please try again.'),
  ).toBeInTheDocument();

  await act(() =>
    router.navigate('/judge/contest/1/theme/3/rate?submission=22'),
  );
  expect(await screen.findByRole('img', { name: 'Bridge' })).toBeVisible();
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
  expect(router.state.location.search).toBe('?submission=22');
});

it('reports a theme that is not in the contest', async () => {
  const submissionLoads: unknown[] = [];
  // Theme 99 belongs to another contest, so the judge's list for it is empty.
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': ({ params }) => {
      submissionLoads.push(params.theme);
      return page([]);
    },
  });
  renderRater('/judge/contest/1/theme/99/rate');
  expect(
    await screen.findByText('The requested content is no longer available.'),
  ).toBeInTheDocument();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(submissionLoads).toEqual([]);
});
