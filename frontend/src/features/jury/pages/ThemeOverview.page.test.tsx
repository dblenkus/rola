import { render, screen, within, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import '../../../app/i18n/config';
import { page, serveApi } from '../../../test/api';
import { author, submission } from '../../../test/fixtures';
import type { ResultsSubmission } from '../../../shared/api/types';
import ThemeOverview from './ThemeOverview';

const entry: ResultsSubmission = {
  ...submission(11, 'Bridges'),
  description: 'Over the river.',
  author: { ...author, reward: null, reward_theme: null, country: null },
  files: [21, 22].flatMap((id) => submission(id, '').files),
  accepted: true,
  rating: 40,
  reward_kind: null,
  reward_label: null,
};

function renderOverview() {
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

it('heads the overview with one title and names the document after it', async () => {
  serveApi({ 'GET /results/submission': () => page([entry]) });
  renderOverview();

  expect(
    await screen.findByRole('heading', { level: 1, name: 'Results overview' }),
  ).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  await waitFor(() => expect(document.title).toBe('Results overview · Rola'));
});

it('links each photograph to its full file in a new tab', async () => {
  serveApi({ 'GET /results/submission': () => page([entry]) });
  renderOverview();

  const [figure] = await screen.findAllByRole('figure');
  if (!figure) {
    throw new Error('No entry');
  }
  const links = within(figure).getAllByRole('link', { name: 'Bridges' });
  expect(links.map((link) => link.getAttribute('href'))).toEqual([
    'https://media.example/21.jpg',
    'https://media.example/22.jpg',
  ]);
  for (const link of links) {
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(within(link).getByRole('img')).toHaveAttribute('loading', 'lazy');
  }
  expect(within(figure).getByText('Bridges')).toBeVisible();
  expect(within(figure).getByText('Over the river.')).toBeVisible();
  expect(
    within(figure).getByText('Points: 40, Author: 4, Submission id: 11'),
  ).toBeVisible();
});
