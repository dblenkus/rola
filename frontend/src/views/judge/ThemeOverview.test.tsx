import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import { page, serveApi } from '../../test/api';
import { author, submission } from '../../test/fixtures';
import type { ResultsSubmission } from '../../shared/api/types';
import ThemeOverview from './ThemeOverview';

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
    accepted: false,
    rating: 40,
    reward_kind: null,
    reward_label: null,
  };
  serveApi({ 'GET /results/submission': () => page([series]) });

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
  serveApi({ 'GET /results/submission': () => page([]) });

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
