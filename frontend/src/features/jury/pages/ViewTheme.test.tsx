import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Provider } from 'react-redux';
import {
  createMemoryRouter,
  MemoryRouter,
  Route,
  RouterProvider,
  Routes,
} from 'react-router';
import { expect, it } from 'vitest';
import '../../../app/i18n/config';
import { createAppStore } from '../../../app/store';
import { httpError, page, ratingSaves, serveApi } from '../../../test/api';
import { contest, jurySubmission } from '../../../test/fixtures';
import type {
  JurySubmission,
  PaginatedResponse,
} from '../../../shared/api/types';
import RateSubmission from './RateSubmission';
import ViewTheme from './ViewTheme';

const twoThemes = {
  ...contest,
  themes: [...contest.themes, { ...contest.themes[0]!, id: 3, title: 'City' }],
};

function renderGallery(store: ReturnType<typeof createAppStore>, path: string) {
  render(
    <Provider store={store}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/judge/contest/:contestId/theme/:themeId"
            element={<ViewTheme />}
          />
        </Routes>
      </MemoryRouter>
    </Provider>,
  );
}

it('shows nothing from the previous theme while another theme loads', async () => {
  const store = createAppStore();
  serveApi({
    'GET /contests/1': () => twoThemes,
    'GET /judging/submissions': () => page([jurySubmission(11, 'First')]),
    'GET /judging/ratings': () => page([]),
  });
  renderGallery(store, '/judge/contest/1/theme/2');
  expect(
    await screen.findByRole('heading', { name: 'Nature' }),
  ).toBeInTheDocument();
  cleanup();

  serveApi({
    'GET /contests/1': () => twoThemes,
    'GET /judging/submissions': () => new Promise(() => {}),
    'GET /judging/ratings': () => page([]),
  });
  renderGallery(store, '/judge/contest/1/theme/3');
  expect(await screen.findByRole('progressbar')).toBeInTheDocument();
  expect(screen.queryByRole('heading')).not.toBeInTheDocument();
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
});

it('opens the rater on the clicked photograph only once it has loaded', async () => {
  const store = createAppStore();
  const saves: unknown[] = [];
  let loads = 0;
  let answer: (data: PaginatedResponse<JurySubmission>) => void = () => {};
  const photographs = [
    jurySubmission(11, 'First'),
    jurySubmission(12, 'Second'),
  ];
  serveApi({
    'GET /contests/1': () => twoThemes,
    'GET /judging/submissions': () => {
      loads += 1;
      // The gallery's load answers at once, the rater's when the test says.
      return loads === 1
        ? page(photographs)
        : new Promise((resolve) => {
            answer = resolve;
          });
    },
    'GET /judging/ratings': () => page([]),
    ...ratingSaves([11, 12], (save, answer) => {
      saves.push(save);
      return answer;
    }),
  });
  render(
    <Provider store={store}>
      <MemoryRouter initialEntries={['/judge/contest/1/theme/2']}>
        <Routes>
          <Route
            path="/judge/contest/:contestId/theme/:themeId"
            element={<ViewTheme />}
          />
          <Route
            path="/judge/contest/:contestId/theme/:themeId/rate"
            element={<RateSubmission />}
          />
        </Routes>
      </MemoryRouter>
    </Provider>,
  );
  const user = userEvent.setup();
  await user.click(await screen.findByRole('img', { name: 'First' }));
  expect(await screen.findByRole('progressbar')).toBeInTheDocument();
  await waitFor(() => expect(loads).toBe(2));
  await user.keyboard('5');
  expect(saves).toEqual([]);

  answer(page(photographs));
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await user.keyboard('5');
  await waitFor(() =>
    expect(saves).toEqual([{ submission: 11, body: { rating: 5 } }]),
  );
  // A score stays on its photograph; the judge moves on with Next.
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
  expect(screen.queryByRole('img', { name: 'Second' })).not.toBeInTheDocument();
});

it('shows no ratings error from a theme the gallery has left', async () => {
  const store = createAppStore();
  let failFirstTheme: (() => void) | undefined;
  serveApi({
    'GET /contests/1': () => twoThemes,
    'GET /judging/submissions': (config) =>
      page([
        config.params.theme === 2
          ? jurySubmission(11, 'First')
          : jurySubmission(21, 'Street'),
      ]),
    'GET /judging/ratings': (config) =>
      config.params.theme === 2
        ? new Promise((_resolve, reject) => {
            failFirstTheme = () => reject(httpError(config, 503));
          })
        : page([]),
  });
  const router = createMemoryRouter(
    [
      {
        path: '/judge/contest/:contestId/theme/:themeId',
        element: <ViewTheme />,
      },
    ],
    { initialEntries: ['/judge/contest/1/theme/2'] },
  );
  render(
    <Provider store={store}>
      <RouterProvider router={router} />
    </Provider>,
  );
  await waitFor(() => expect(failFirstTheme).toBeDefined());

  // The same route stays mounted, as after a jump in the browser history.
  await act(() => router.navigate('/judge/contest/1/theme/3'));
  expect(
    await screen.findByRole('heading', { name: 'City' }),
  ).toBeInTheDocument();
  await act(async () => failFirstTheme?.());
  expect(screen.getByRole('heading', { name: 'City' })).toBeInTheDocument();
  expect(
    screen.queryByText('Request failed. Please try again.'),
  ).not.toBeInTheDocument();
});

it('reports a theme that is not in the contest', async () => {
  const store = createAppStore();
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
  renderGallery(store, '/judge/contest/1/theme/99');
  expect(
    await screen.findByText('The requested content is no longer available.'),
  ).toBeInTheDocument();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(submissionLoads).toEqual([]);
});
