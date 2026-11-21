import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import { page, serveApi } from '../../../test/api';
import { author, submission } from '../../../test/fixtures';
import type { ResultsSubmission } from '../../../shared/api/types';
import ThemeOverview from './ThemeOverview';

function renderOverview(): void {
  render(
    <MemoryRouter initialEntries={['/judge/contest/1/theme/2/overview']}>
      <Routes>
        <Route
          path="/judge/contest/:contestId/theme/:themeId/overview"
          element={<ThemeOverview />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

function result(
  id: number,
  title: string,
  score: number | null,
): ResultsSubmission {
  return {
    ...submission(id, title),
    author: {
      ...author,
      reward: null,
      reward_theme: null,
      country: null,
    },
    files: score === null ? null : submission(id, title).files,
    accepted: score !== null,
    score,
    reward_kind: null,
    reward_label: null,
  };
}

it('shows a series of more than six photographs in full', async () => {
  const ids = [21, 22, 23, 24, 25, 26, 27, 28];
  const series: ResultsSubmission = {
    ...submission(11, 'Bridges'),
    author: {
      ...author,
      reward: null,
      reward_theme: null,
      country: null,
    },
    files: ids.flatMap((id) => submission(id, '').files),
    accepted: true,
    score: 40,
    reward_kind: null,
    reward_label: null,
  };
  serveApi({ 'GET /results/submissions': () => page([series]) });

  render(
    <MemoryRouter initialEntries={['/judge/contest/1/theme/2/overview']}>
      <Routes>
        <Route
          path="/judge/contest/:contestId/theme/:themeId/overview"
          element={<ThemeOverview />}
        />
      </Routes>
    </MemoryRouter>,
  );

  expect(
    (await screen.findAllByRole('img', { name: 'Bridges' })).map((image) =>
      image.getAttribute('src'),
    ),
  ).toEqual(ids.map((id) => `https://media.example/${id}.jpg`));
});

it('says so while the theme has no published results', async () => {
  serveApi({ 'GET /results/submissions': () => page([]) });

  render(
    <MemoryRouter initialEntries={['/judge/contest/1/theme/2/overview']}>
      <Routes>
        <Route
          path="/judge/contest/:contestId/theme/:themeId/overview"
          element={<ThemeOverview />}
        />
      </Routes>
    </MemoryRouter>,
  );

  expect(await screen.findByText('No published results.')).toBeVisible();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
});

it('shows the accepted entries from every page by score, then id', async () => {
  serveApi({
    'GET /results/submissions': (_config, url) => {
      if (url.searchParams.get('theme') !== '2') {
        throw new Error(`Unexpected results query: ${url.search}`);
      }
      return url.searchParams.get('page') === '2'
        ? page([result(14, 'Fog', 30), result(15, 'Rain', null)])
        : {
            ...page([
              result(11, 'Hills', 20),
              result(12, 'Snow', null),
              result(13, 'Lake', 30),
              result(10, 'Sea', 20),
            ]),
            next: '/api/v1/results/submissions?page=2&theme=2',
          };
    },
  });

  renderOverview();

  expect(
    (await screen.findAllByRole('img')).map((image) =>
      image.getAttribute('alt'),
    ),
  ).toEqual(['Lake', 'Fog', 'Sea', 'Hills']);
});

it('says so while no entry of the theme is accepted', async () => {
  serveApi({
    'GET /results/submissions': () =>
      page([result(12, 'Snow', null), result(15, 'Rain', null)]),
  });

  renderOverview();

  expect(await screen.findByText('No published results.')).toBeVisible();
  expect(screen.queryByText('Snow')).not.toBeInTheDocument();
});
