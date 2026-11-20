import { render, screen, within, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { expect, it } from 'vitest';
import '../../../app/i18n/config';
import { page, serveApi } from '../../../test/api';
import { contest } from '../../../test/fixtures';
import type { JuryContest, JuryTheme } from '../../../shared/api/types';
import SelectTheme from './SelectTheme';

function juryTheme(
  id: number,
  title: string,
  ratings: number,
  submissions: number,
): JuryTheme {
  return {
    id,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    title,
    is_series: false,
    max_photos: 2,
    rating_count: ratings,
    submission_count: submissions,
  };
}

const juryContest: JuryContest = {
  ...contest,
  themes: [juryTheme(2, 'Nature', 12, 40), juryTheme(3, 'City', 0, 0)],
};

function renderPage() {
  render(
    <MemoryRouter>
      <SelectTheme />
    </MemoryRouter>,
  );
}

it('heads the page with one title and names the document after it', async () => {
  serveApi({ 'GET /judging/contests': () => page([juryContest]) });
  renderPage();

  expect(
    await screen.findByRole('heading', { level: 1, name: 'Judging' }),
  ).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  await waitFor(() => expect(document.title).toBe('Judging · Rola'));
  expect(
    screen.getByRole('heading', { level: 2, name: 'Autumn photographs' }),
  ).toBeInTheDocument();
});

it('shows each theme with its scoring progress and a link to its gallery', async () => {
  serveApi({ 'GET /judging/contests': () => page([juryContest]) });
  renderPage();

  const [nature, city] = await screen.findAllByRole('listitem');
  if (!nature || !city) {
    throw new Error('Missing theme rows');
  }
  expect(within(nature).getByText('Nature')).toBeVisible();
  expect(within(nature).getByText('12 / 40')).toBeVisible();
  const strip = within(nature).getByRole('progressbar', {
    name: 'Nature, scored 12 of 40',
  });
  expect(strip).toHaveAttribute('aria-valuenow', '12');
  expect(strip).toHaveAttribute('aria-valuemax', '40');
  expect(
    within(nature).getByRole('link', { name: 'Open Nature' }),
  ).toHaveAttribute('href', '/judge/contest/1/theme/2');

  // A theme without photographs has nothing to draw a share of.
  expect(within(city).getByText('0 / 0')).toBeVisible();
  expect(within(city).queryByRole('progressbar')).not.toBeInTheDocument();
  expect(within(city).getByRole('link', { name: 'Open City' })).toHaveAttribute(
    'href',
    '/judge/contest/1/theme/3',
  );
});

it('says so when the judge has no contests', async () => {
  serveApi({ 'GET /judging/contests': () => page([]) });
  renderPage();

  expect(
    await screen.findByText('You have no contests to judge.'),
  ).toBeVisible();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
});
