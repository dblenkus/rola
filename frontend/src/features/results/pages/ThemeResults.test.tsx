import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import { serveApi } from '../../../test/api';
import { author, contest } from '../../../test/fixtures';
import type { ResultsThemeSubmission } from '../../../shared/api/types';
import ThemeResults from './ThemeResults';

function result(
  id: number,
  title: string,
  overrides: Partial<ResultsThemeSubmission> = {},
): ResultsThemeSubmission {
  return {
    id,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    author: {
      ...author,
      reward: null,
      reward_theme: null,
      country: 'SI',
    },
    theme: 2,
    title,
    files: null,
    accepted: false,
    reward_kind: null,
    reward_label: null,
    ...overrides,
  };
}

function renderTheme(submissions: ResultsThemeSubmission[]): void {
  const [nature] = contest.themes;
  if (!nature) {
    throw new Error('The contest fixture has no theme');
  }
  serveApi({
    'GET /contest/1': () => contest,
    'GET /results/theme/2': () => ({ ...nature, submissions }),
  });
  render(
    <MemoryRouter initialEntries={['/results/contest/1/theme/2']}>
      <Routes>
        <Route
          path="/results/contest/:contestId/theme/:themeId"
          element={<ThemeResults />}
        />
        <Route
          path="/results/contest/:contestId/theme/:themeId/submission/:submissionId"
          element={<p>Submission page</p>}
        />
      </Routes>
    </MemoryRouter>,
  );
}

const entries = [
  result(21, 'Hills'),
  result(22, 'Lake', { accepted: true }),
  result(23, 'Fog', {
    accepted: true,
    reward_kind: 'Gold',
    reward_label: 'Gold medal',
  }),
  result(24, 'Rain', {
    accepted: true,
    reward_kind: 'Honorable Mention',
    reward_label: 'Honorable mention',
  }),
];

function row(title: string): HTMLElement {
  return screen.getByRole('row', { name: new RegExp(`^${title}`) });
}

function awardNames(element: HTMLElement): (string | null)[] {
  return Array.from(element.querySelectorAll('.rl-award')).map(
    (mark) => mark.textContent,
  );
}

it('titles the page with the theme and the contest', async () => {
  renderTheme(entries);
  expect(
    await screen.findByRole('heading', { level: 1, name: 'Nature' }),
  ).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(screen.getByText('Autumn photographs')).toBeInTheDocument();
  expect(document.title).toBe('Nature · Rola');
});

it('marks awarded entries with the award and accepted ones with a check', async () => {
  renderTheme(entries);
  await screen.findByText('Hills');

  const plain = row('Hills');
  expect(plain).toHaveTextContent(/^Hills$/);
  expect(awardNames(plain)).toEqual([]);
  expect(plain.querySelector('svg')).toBeNull();

  const accepted = row('Lake');
  expect(accepted).toHaveTextContent(/^LakeAccepted$/);
  expect(awardNames(accepted)).toEqual([]);
  expect(accepted.querySelector('svg')).toBeInTheDocument();

  expect(row('Fog')).toHaveTextContent(/^FogGold medal$/);
  expect(awardNames(row('Fog'))).toEqual(['Gold medal']);
  expect(awardNames(row('Rain'))).toEqual(['Honorable mention']);
});

it('links the titles of accepted entries only', async () => {
  renderTheme(entries);
  await screen.findByText('Hills');

  expect(
    screen.getAllByRole('link').map((link) => link.getAttribute('href')),
  ).toEqual([
    '/results/contest/1/theme/2/submission/22',
    '/results/contest/1/theme/2/submission/23',
    '/results/contest/1/theme/2/submission/24',
  ]);
  expect(
    within(row('Hills')).queryByRole('link', { name: 'Hills' }),
  ).not.toBeInTheDocument();
});

it('stays on the results when a row without a link is clicked', async () => {
  const user = userEvent.setup();
  renderTheme(entries);
  await user.click(await screen.findByText('Hills'));
  await user.click(row('Hills'));
  expect(screen.queryByText('Submission page')).not.toBeInTheDocument();
  expect(screen.getByText('Hills')).toBeInTheDocument();
});

it('opens an accepted entry from its title', async () => {
  const user = userEvent.setup();
  renderTheme(entries);
  await user.click(await screen.findByRole('link', { name: 'Lake' }));
  await waitFor(() =>
    expect(screen.getByText('Submission page')).toBeInTheDocument(),
  );
});

it('names an untitled entry', async () => {
  renderTheme([result(25, '', { accepted: true })]);
  expect(await screen.findByRole('link', { name: 'Untitled' })).toHaveAttribute(
    'href',
    '/results/contest/1/theme/2/submission/25',
  );
});

it('says so when the theme has no published results', async () => {
  renderTheme([]);
  expect(await screen.findByText('No published results.')).toBeVisible();
  expect(screen.queryByRole('table')).not.toBeInTheDocument();
});

it('renders no Material UI', async () => {
  renderTheme(entries);
  await screen.findByText('Hills');
  expect(document.querySelector('[class*="Mui"]')).toBeNull();
});
