import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Provider } from 'react-redux';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import '../../i18n/config';
import store from '../../store';
import { httpError, page, serveApi } from '../../test/api';
import { contest, submission } from '../../test/fixtures';
import type { PaginatedResponse, Rating } from '../../types/api';
import RateSubmission from './RateSubmission';

interface PendingRating {
  submission: number;
  resolve: (data: PaginatedResponse<Rating>) => void;
}

const pending: PendingRating[] = [];

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

function renderRater() {
  render(
    <Provider store={store}>
      <MemoryRouter
        initialEntries={['/judge/contest/1/theme/2/rate?submission=11']}
      >
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

it('keeps the rater after a failed rating load', async () => {
  let unavailable = true;
  const saves: unknown[] = [];
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () =>
      page([submission(11, 'First'), submission(12, 'Second')]),
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
    'GET /judge/submission': () => page([submission(11, 'First')]),
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
      page([submission(11, 'First'), submission(12, 'Second')]),
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
      page([submission(11, 'First'), submission(12, 'Second')]),
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

it('keeps the rater after a failed save', async () => {
  let attempts = 0;
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () =>
      page([submission(11, 'First'), submission(12, 'Second')]),
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
