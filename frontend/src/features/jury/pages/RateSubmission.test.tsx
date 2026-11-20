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
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import '../../../app/i18n/config';
import { createAppStore, type AppStore } from '../../../app/store';
import {
  httpError,
  page,
  ratingSaves,
  serveApi,
  withStatus,
} from '../../../test/api';
import { contest, jurySubmission } from '../../../test/fixtures';
import type {
  JurySubmission,
  PaginatedResponse,
  Rating,
} from '../../../shared/api/types';
import RateSubmission from './RateSubmission';
import { pressedScore, scoreKey } from './RateSubmission.testutils';

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

afterEach(() => {
  vi.restoreAllMocks();
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

it('keeps the rater after a failed rating load', async () => {
  let unavailable = true;
  const saves: unknown[] = [];
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': () =>
      page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
    'GET /judging/ratings': (config) => {
      if (config.params.submission !== 12) return page([]);
      if (unavailable) {
        throw httpError(config, 503);
      }
      return ratings(12, 4);
    },
    ...ratingSaves([11, 12], (save, answer) => {
      saves.push(save);
      return answer;
    }),
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
  await waitFor(() => expect(pressedScore()).toBe(6));
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
  expect(saves).toEqual([{ submission: 12, body: { rating: 6 } }]);

  unavailable = false;
  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
});

it('ignores rating keys when the theme does not load', async () => {
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': () => page([jurySubmission(11, 'First')]),
    'GET /judging/ratings': () => page([]),
  });
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  cleanup();

  const saves: unknown[] = [];
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': (config) => {
      throw httpError(config, 503);
    },
    'GET /judging/ratings': () => page([]),
    ...ratingSaves([11], (save, answer) => {
      saves.push(save);
      return answer;
    }),
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
    'GET /contests/1': () => contest,
    'GET /judging/submissions': () =>
      page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
    // The theme-wide ratings answer at once; each submission's own waits.
    'GET /judging/ratings': ({ params }) =>
      params.theme !== undefined
        ? page([])
        : new Promise((resolve) =>
            pending.push({ submission: params.submission, resolve }),
          ),
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await answerRating(12, 5);
  expect(pressedScore()).toBe(5);
  await answerRating(11, 7);
  expect(pressedScore()).toBe(5);

  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  expect(pressedScore()).toBe(0);
  await answerRating(11, 7);
  expect(pressedScore()).toBe(7);
});

it('stays on the shown submission when an earlier save finishes', async () => {
  const saves: (() => void)[] = [];
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': () =>
      page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
    'GET /judging/ratings': ({ params }) =>
      params.submission === 12 ? ratings(12, 3) : page([]),
    ...ratingSaves(
      [11, 12],
      (_save, answer) =>
        new Promise((resolve) => saves.push(() => resolve(answer))),
    ),
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('5');
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(3));
  expect(saves).toHaveLength(1);
  saves[0]?.();
  await settle();
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(pressedScore()).toBe(3);
});

it('keeps the next rater on its submission when a closed rater saves late', async () => {
  const saves: (() => void)[] = [];
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': () =>
      page([
        jurySubmission(11, 'First'),
        jurySubmission(12, 'Second'),
        jurySubmission(13, 'Third'),
      ]),
    'GET /judging/ratings': () => page([]),
    ...ratingSaves(
      [11, 12, 13],
      (_save, answer) =>
        new Promise((resolve) => saves.push(() => resolve(answer))),
    ),
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
  expect(pressedScore()).toBe(0);
});

it('ignores new ratings while a rating save is pending', async () => {
  const saves: unknown[] = [];
  const answers: (() => void)[] = [];
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': () =>
      page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
    'GET /judging/ratings': () => page([]),
    ...ratingSaves([11, 12], (save, answer) => {
      saves.push(save);
      return new Promise((resolve) => answers.push(() => resolve(answer)));
    }),
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('5');
  await waitFor(() => expect(saves).toHaveLength(1));
  await user.keyboard('7');
  await user.click(scoreKey(7));
  await settle();
  expect(saves).toEqual([{ submission: 11, body: { rating: 5 } }]);
  expect(pressedScore()).toBe(0);

  answers[0]?.();
  await waitFor(() => expect(pressedScore()).toBe(5));
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
  await user.keyboard('7');
  await waitFor(() => expect(saves).toHaveLength(2));
  expect(saves).toEqual([
    { submission: 11, body: { rating: 5 } },
    { submission: 11, body: { rating: 7 } },
  ]);
});

it('ignores auto-repeated digit keys but not arrow keys', async () => {
  const saves: unknown[] = [];
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': () =>
      page([
        jurySubmission(11, 'First'),
        jurySubmission(12, 'Second'),
        jurySubmission(13, 'Third'),
      ]),
    'GET /judging/ratings': () => page([]),
    ...ratingSaves([11, 12, 13], (save, answer) => {
      saves.push(save);
      return answer;
    }),
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('7');
  await waitFor(() => expect(pressedScore()).toBe(7));
  // fireEvent dispatches at once; the rater listens for keys on the shown
  // submission only after its effects have run.
  await settle();
  fireEvent.keyDown(window, { key: '7', repeat: true });
  await settle();
  expect(saves).toEqual([{ submission: 11, body: { rating: 7 } }]);
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();

  fireEvent.keyDown(window, { key: 'ArrowRight', repeat: true });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await settle();
  fireEvent.keyDown(window, { key: 'ArrowRight', repeat: true });
  expect(await screen.findByRole('img', { name: 'Third' })).toBeVisible();
});

it('keeps the rater after a failed save', async () => {
  let attempts = 0;
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': () =>
      page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
    'GET /judging/ratings': () => page([]),
    ...ratingSaves([11, 12], (_save, answer, config) => {
      attempts += 1;
      if (attempts === 1) {
        throw httpError(config, 400, {
          rating: ['Ensure this value is less than or equal to 10.'],
        });
      }
      return answer;
    }),
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
  await waitFor(() => expect(pressedScore()).toBe(5));
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
  expect(attempts).toBe(2);
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
});

it.each([
  { status: 201, saved: 'created', before: [] },
  { status: 200, saved: 'replaced', before: [3] },
])(
  'puts the rating and shows it when the server reports it $saved',
  async ({ status, before }) => {
    const requests: unknown[] = [];
    serveApi({
      'GET /contests/1': () => contest,
      'GET /judging/submissions': () =>
        page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
      'GET /judging/ratings': ({ params }) =>
        params.submission === 11 && before.length
          ? ratings(11, before[0] ?? 0)
          : page([]),
      'PUT /judging/ratings/11': (config) => {
        requests.push({
          method: config.method,
          url: config.url,
          body: JSON.parse(String(config.data)),
        });
        return withStatus(status, {
          id: 1,
          created: '2026-01-01T00:00:00Z',
          modified: '2026-01-02T00:00:00Z',
          submission: 11,
          rating: 7,
        });
      },
    });
    const user = userEvent.setup();
    renderRater();
    expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
    await waitFor(() => expect(pressedScore()).toBe(before[0] ?? 0));

    await user.keyboard('7');
    await waitFor(() => expect(pressedScore()).toBe(7));
    expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
    expect(requests).toEqual([
      { method: 'put', url: '/judging/ratings/11', body: { rating: 7 } },
    ]);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);

it.each([
  {
    status: 403,
    detail:
      'The results of this contest are published, so its ratings are final.',
    shown: 'You do not have permission to perform this action.',
  },
  {
    status: 404,
    detail: 'There is no submission with this id that you can rate.',
    shown: 'The requested content is no longer available.',
  },
])(
  'keeps the rater and explains a save refused with $status',
  async ({ status, detail, shown }) => {
    serveApi({
      'GET /contests/1': () => contest,
      'GET /judging/submissions': () =>
        page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]),
      'GET /judging/ratings': () => page([]),
      ...ratingSaves([11], (_save, _answer, config) => {
        throw httpError(config, status, { detail });
      }),
    });
    const user = userEvent.setup();
    renderRater();
    expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

    await user.keyboard('5');
    expect(await screen.findByRole('alert')).toHaveTextContent(shown);
    expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
    expect(pressedScore()).toBe(0);
  },
);

const twoThemes = {
  ...contest,
  themes: [...contest.themes, { ...contest.themes[0]!, id: 3, title: 'City' }],
};

it('shows nothing from the previous theme while another theme loads', async () => {
  serveApi({
    'GET /contests/1': () => twoThemes,
    'GET /judging/submissions': () => page([jurySubmission(11, 'First')]),
    'GET /judging/ratings': () => page([]),
  });
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  cleanup();

  const saves: unknown[] = [];
  const ratingLoads: unknown[] = [];
  let answer: (data: PaginatedResponse<JurySubmission>) => void = () => {};
  serveApi({
    'GET /contests/1': () => twoThemes,
    'GET /judging/submissions': () =>
      new Promise((resolve) => {
        answer = resolve;
      }),
    // Only a submission's own ratings belong to the theme shown.
    'GET /judging/ratings': ({ params }) => {
      if (params.submission !== undefined) ratingLoads.push(params.submission);
      return page([]);
    },
    ...ratingSaves([21], (save, answer) => {
      saves.push(save);
      return answer;
    }),
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
    'GET /contests/1': () => twoThemes,
    'GET /judging/submissions': ({ params }) =>
      new Promise((resolve) => answers.set(String(params.theme), resolve)),
    'GET /judging/ratings': () => page([]),
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
    'GET /contests/1': () => twoThemes,
    'GET /judging/submissions': (config) =>
      config.params.theme === 2
        ? new Promise((_resolve, reject) => {
            failFirstTheme = () => reject(httpError(config, 503));
          })
        : page([jurySubmission(21, 'Street')]),
    'GET /judging/ratings': () => page([]),
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
    'GET /contests/1': () => twoThemes,
    'GET /judging/submissions': (config) => {
      if (config.params.theme === 2) throw httpError(config, 503);
      return page([jurySubmission(21, 'Street'), jurySubmission(22, 'Bridge')]);
    },
    'GET /judging/ratings': () => page([]),
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
    'GET /contests/1': () => contest,
    'GET /judging/submissions': ({ params }) => {
      submissionLoads.push(params.theme);
      return page([]);
    },
    'GET /judging/ratings': () => page([]),
  });
  renderRater('/judge/contest/1/theme/99/rate');
  expect(
    await screen.findByText('The requested content is no longer available.'),
  ).toBeInTheDocument();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(submissionLoads).toEqual([]);
});

it('reloads expired photograph links at most once a minute', async () => {
  let loads = 0;
  serveApi({
    'GET /contests/1': () => contest,
    // Every load signs the links anew, as the server does.
    'GET /judging/submissions': () => {
      loads += 1;
      return page(
        [jurySubmission(11, 'First'), jurySubmission(12, 'Second')].map(
          (submission) => ({
            ...submission,
            files: submission.files.map((file) => ({
              ...file,
              file: `${file.file}?v=${loads}`,
            })),
          }),
        ),
      );
    },
    'GET /judging/ratings': () => page([]),
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await user.keyboard('{ArrowRight}');
  const expired = await screen.findByRole('img', { name: 'Second' });
  expect(expired).toHaveAttribute('src', 'https://media.example/12.jpg?v=1');

  fireEvent.error(expired);
  await waitFor(() =>
    expect(screen.getByRole('img', { name: 'Second' })).toHaveAttribute(
      'src',
      'https://media.example/12.jpg?v=2',
    ),
  );
  expect(loads).toBe(2);

  fireEvent.error(screen.getByRole('img', { name: 'Second' }));
  await settle();
  expect(loads).toBe(2);
  expect(screen.getByRole('img', { name: 'Second' })).toHaveAttribute(
    'src',
    'https://media.example/12.jpg?v=2',
  );

  vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 60_001);
  fireEvent.error(screen.getByRole('img', { name: 'Second' }));
  await waitFor(() =>
    expect(screen.getByRole('img', { name: 'Second' })).toHaveAttribute(
      'src',
      'https://media.example/12.jpg?v=3',
    ),
  );
  expect(loads).toBe(3);
});

it('keeps the rater when reloading photograph links fails', async () => {
  let failing = false;
  let loads = 0;
  const saves: unknown[] = [];
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': (config) => {
      loads += 1;
      if (failing) throw httpError(config, 503);
      return page([jurySubmission(11, 'First'), jurySubmission(12, 'Second')]);
    },
    'GET /judging/ratings': () => page([]),
    ...ratingSaves([11, 12], (save, answer) => {
      saves.push(save);
      return answer;
    }),
  });
  const user = userEvent.setup();
  renderRater();
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await user.keyboard('{ArrowRight}');
  const shown = await screen.findByRole('img', { name: 'Second' });

  failing = true;
  fireEvent.error(shown);
  expect(
    await screen.findByText('Request failed. Please try again.'),
  ).toBeInTheDocument();
  expect(loads).toBe(2);
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();

  // The failure belongs to the submission whose photograph failed.
  failing = false;
  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
  await user.keyboard('7');
  await waitFor(() =>
    expect(saves).toEqual([{ submission: 11, body: { rating: 7 } }]),
  );
  await user.keyboard('{ArrowRight}');

  // Once its photograph loads, nothing is left to retry.
  fireEvent.load(await screen.findByRole('img', { name: 'Second' }));
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();

  // The failed reload does not hold back the next one.
  fireEvent.error(screen.getByRole('img', { name: 'Second' }));
  await waitFor(() => expect(loads).toBe(3));
  await settle();
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
});

it('shows a failed reload on every submission whose photograph failed during it', async () => {
  let loads = 0;
  const failures: (() => void)[] = [];
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': (config) => {
      loads += 1;
      if (loads === 1)
        return page([
          jurySubmission(11, 'First'),
          jurySubmission(12, 'Second'),
          jurySubmission(13, 'Third'),
        ]);
      return new Promise((_resolve, reject) =>
        failures.push(() => reject(httpError(config, 503))),
      );
    },
    'GET /judging/ratings': () => page([]),
  });
  const user = userEvent.setup();
  renderRater('/judge/contest/1/theme/2/rate?submission=12');
  fireEvent.error(await screen.findByRole('img', { name: 'Second' }));
  await waitFor(() => expect(failures).toHaveLength(1));
  await user.keyboard('{ArrowRight}');
  fireEvent.error(await screen.findByRole('img', { name: 'Third' }));

  failures[0]?.();
  expect(
    await screen.findByText('Request failed. Please try again.'),
  ).toBeInTheDocument();
  expect(loads).toBe(2);

  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  expect(
    screen.getByText('Request failed. Please try again.'),
  ).toBeInTheDocument();

  // A submission whose photographs never failed has nothing to retry.
  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
});

const signedSubmissions = (list: JurySubmission[], load: number) =>
  page(
    list.map((submission) => ({
      ...submission,
      files: submission.files.map((file) => ({
        ...file,
        file: `${file.file}?v=${load}`,
      })),
    })),
  );

// Answers the first load of the theme's submissions at once and holds the
// later ones until the test releases them.
function heldReloads(lists: JurySubmission[][]) {
  let loads = 0;
  const release: (() => void)[] = [];
  const handler = () => {
    loads += 1;
    const load = loads;
    const list = lists[Math.min(load, lists.length) - 1] ?? [];
    if (load === 1) return signedSubmissions(list, load);
    return new Promise<PaginatedResponse<JurySubmission>>((resolve) =>
      release.push(() => resolve(signedSubmissions(list, load))),
    );
  };
  return { handler, release };
}

const threeSubmissions = [
  jurySubmission(11, 'First'),
  jurySubmission(12, 'Second'),
  jurySubmission(13, 'Third'),
];

it('stays on the submission the judge moved to while photograph links reload', async () => {
  const held = heldReloads([threeSubmissions]);
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': held.handler,
    'GET /judging/ratings': () => page([]),
  });
  const user = userEvent.setup();
  const router = createMemoryRouter(
    [
      {
        path: '/judge/contest/:contestId/theme/:themeId/rate',
        element: <RateSubmission />,
      },
    ],
    { initialEntries: ['/judge/contest/1/theme/2/rate?submission=12'] },
  );
  render(
    <Provider store={store}>
      <RouterProvider router={router} />
    </Provider>,
  );
  fireEvent.error(await screen.findByRole('img', { name: 'Second' }));
  await waitFor(() => expect(held.release).toHaveLength(1));
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Third' })).toBeVisible();

  held.release[0]?.();
  await waitFor(() =>
    expect(screen.getByRole('img', { name: 'Third' })).toHaveAttribute(
      'src',
      'https://media.example/13.jpg?v=2',
    ),
  );
  expect(screen.queryByRole('img', { name: 'Second' })).not.toBeInTheDocument();
  expect(router.state.location.search).toBe('?submission=13');
});

it('stays on the last submission when a save finishes after a reload shortened the list', async () => {
  const held = heldReloads([threeSubmissions, threeSubmissions.slice(0, 2)]);
  const answers: (() => void)[] = [];
  serveApi({
    'GET /contests/1': () => contest,
    'GET /judging/submissions': held.handler,
    'GET /judging/ratings': () => page([]),
    ...ratingSaves(
      [11, 12, 13],
      (_save, answer) =>
        new Promise((resolve) => answers.push(() => resolve(answer))),
    ),
  });
  const user = userEvent.setup();
  renderRater('/judge/contest/1/theme/2/rate?submission=12');
  const second = await screen.findByRole('img', { name: 'Second' });
  await user.keyboard('5');
  await waitFor(() => expect(answers).toHaveLength(1));
  fireEvent.error(second);
  await waitFor(() => expect(held.release).toHaveLength(1));
  held.release[0]?.();
  await waitFor(() =>
    expect(screen.getByRole('img', { name: 'Second' })).toHaveAttribute(
      'src',
      'https://media.example/12.jpg?v=2',
    ),
  );

  answers[0]?.();
  await settle();
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(pressedScore()).toBe(5);
});
