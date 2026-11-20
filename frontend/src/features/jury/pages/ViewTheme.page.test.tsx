import { render, screen, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import '../../../app/i18n/config';
import { createAppStore } from '../../../app/store';
import { page, serveApi } from '../../../test/api';
import { contest, jurySubmission } from '../../../test/fixtures';
import type { JurySubmission, Rating } from '../../../shared/api/types';
import ViewTheme from './ViewTheme';

function rating(submission: number, value: number): Rating {
  return {
    id: submission * 10,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    submission,
    rating: value,
  };
}

function renderTheme(submissions: JurySubmission[], ratings: Rating[]) {
  serveApi({
    'GET /contest/1': () => contest,
    'GET /judge/submission': () => page(submissions),
    'GET /rating': () => page(ratings),
  });
  render(
    <Provider store={createAppStore()}>
      <MemoryRouter initialEntries={['/judge/contest/1/theme/2']}>
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

it('heads the gallery with the theme and how many photographs are scored', async () => {
  renderTheme(
    [
      jurySubmission(11, 'First'),
      jurySubmission(12, 'Second'),
      jurySubmission(13, 'Third'),
    ],
    [rating(11, 8)],
  );

  expect(
    await screen.findByRole('heading', { level: 1, name: 'Nature' }),
  ).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  await waitFor(() => expect(document.title).toBe('Nature · Rola'));
  expect(screen.getByText('1 / 3')).toBeVisible();
  const strip = screen.getByRole('progressbar', { name: 'Scored 1 of 3' });
  expect(strip).toHaveAttribute('aria-valuenow', '1');
  expect(strip).toHaveAttribute('aria-valuemax', '3');
  expect(screen.getByRole('link', { name: /First/ })).toHaveAttribute(
    'href',
    '/judge/contest/1/theme/2/rate?submission=11',
  );
});

it('says so for a theme without photographs, with no strip', async () => {
  renderTheme([], []);

  expect(
    await screen.findByText('This theme has no photographs to judge.'),
  ).toBeVisible();
  expect(screen.getByText('0 / 0')).toBeVisible();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
});
