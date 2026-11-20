import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import { httpError, serveApi } from '../../../test/api';
import { expectFailedPage } from '../../../test/pages';
import { author, submission } from '../../../test/fixtures';
import type { ResultsSubmission } from '../../../shared/api/types';
import SubmissionResults from './SubmissionResults';

function resultsSubmission(
  fileIds: number[],
  overrides: Partial<ResultsSubmission> = {},
): ResultsSubmission {
  return {
    ...submission(11, 'Bridges'),
    author: {
      ...author,
      reward: null,
      reward_theme: null,
      country: 'SI',
    },
    files: fileIds.flatMap((id) => submission(id, '').files),
    accepted: true,
    rating: 40,
    reward_kind: null,
    reward_label: null,
    ...overrides,
  };
}

function renderSubmission(data: ResultsSubmission): void {
  serveApi({ 'GET /results/submission/11': () => data });
  render(
    <MemoryRouter initialEntries={['/results/contest/1/theme/2/submission/11']}>
      <Routes>
        <Route
          path="/results/contest/:contestId/theme/:themeId/submission/:submissionId"
          element={<SubmissionResults />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

it('shows the photo named by its title, with the wall label', async () => {
  renderSubmission(
    resultsSubmission([21], {
      description: 'Morning fog over the river.',
      reward_kind: 'Gold',
      reward_label: 'Gold medal',
    }),
  );

  const photo = await screen.findByRole('img', { name: 'Bridges' });
  expect(photo).toHaveAttribute('src', 'https://media.example/21.jpg');
  expect(photo).toHaveAttribute('loading', 'eager');
  // The wall label's visible title is the page's one h1, not a copy of it.
  const heading = screen.getByRole('heading', { level: 1 });
  expect(heading).toHaveTextContent('Bridges');
  expect(heading).toHaveClass('photo-title');
  expect(heading).not.toHaveClass('visually-hidden');
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(screen.getAllByText('Bridges')).toEqual([heading]);
  await waitFor(() => expect(document.title).toBe('Bridges · Rola'));
  expect(screen.getByText('Ana Novak (SI)')).toBeInTheDocument();
  expect(screen.getByText('Morning fog over the river.')).toBeInTheDocument();
  const marks = document.querySelectorAll('.rl-award');
  expect(marks).toHaveLength(1);
  expect(marks[0]).toHaveTextContent('Gold medal');
});

it('never names the author in the alternative text', async () => {
  renderSubmission(resultsSubmission([21, 22]));
  const photos = await screen.findAllByRole('img');
  for (const photo of photos) {
    expect(photo.getAttribute('alt')).not.toMatch(/Ana|Novak/);
  }
});

it('shows every photo of a long series, the first one eagerly', async () => {
  const ids = [21, 22, 23, 24, 25, 26, 27, 28];
  renderSubmission(resultsSubmission(ids));

  const photos = await screen.findAllByRole('img');
  expect(photos.map((photo) => photo.getAttribute('src'))).toEqual(
    ids.map((id) => `https://media.example/${id}.jpg`),
  );
  expect(photos.map((photo) => photo.getAttribute('alt'))).toEqual(
    ids.map((_, index) => `Bridges, photo ${index + 1} of ${ids.length}`),
  );
  expect(photos.map((photo) => photo.getAttribute('loading'))).toEqual([
    'eager',
    ...ids.slice(1).map(() => 'lazy'),
  ]);
});

it('names an untitled photo', async () => {
  renderSubmission(resultsSubmission([21], { title: null }));
  expect(
    await screen.findByRole('img', { name: 'Untitled' }),
  ).toBeInTheDocument();
  await waitFor(() => expect(document.title).toBe('Untitled · Rola'));
});

it('shows no brackets after an author without a country', async () => {
  renderSubmission(
    resultsSubmission([21], {
      author: { ...author, reward: null, reward_theme: null, country: null },
    }),
  );
  const name = await screen.findByText('Ana Novak');
  expect(name).toHaveTextContent(/^Ana Novak$/);
});

it('shows a failed load on a page named Results', async () => {
  document.title = 'Active contests · Rola';
  serveApi({
    'GET /results/submission/11': (config) => {
      throw httpError(config, 404);
    },
  });
  render(
    <MemoryRouter initialEntries={['/results/contest/1/theme/2/submission/11']}>
      <Routes>
        <Route
          path="/results/contest/:contestId/theme/:themeId/submission/:submissionId"
          element={<SubmissionResults />}
        />
      </Routes>
    </MemoryRouter>,
  );

  await expectFailedPage(
    'Results',
    'The requested content is no longer available.',
  );
});
