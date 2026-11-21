import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  createMemoryRouter,
  MemoryRouter,
  Route,
  RouterProvider,
  Routes,
} from 'react-router';
import { describe, expect, it } from 'vitest';
import { httpError, page, serveApi } from '../../../test/api';
import { expectFailedPage } from '../../../test/pages';
import { author, contest } from '../../../test/fixtures';
import type {
  Contest,
  PaginatedResponse,
  ResultsSubmission,
} from '../../../shared/api/types';
import ThemeResults from './ThemeResults';

function result(
  id: number,
  title: string,
  overrides: Partial<ResultsSubmission> = {},
): ResultsSubmission {
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
    score: null,
    reward_kind: null,
    reward_label: null,
    ...overrides,
  };
}

function renderResults(path: string): void {
  render(
    <MemoryRouter initialEntries={[path]}>
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

function renderTheme(
  submissions: ResultsSubmission[],
  shownContest: Contest = contest,
): void {
  serveApi({
    'GET /contests/1': () => shownContest,
    'GET /results/submissions': (_config, url) =>
      page(url.searchParams.get('theme') === '2' ? submissions : []),
  });
  renderResults('/results/contest/1/theme/2');
}

const entries = [
  result(21, 'Hills'),
  result(22, 'Lake', { accepted: true, score: 31 }),
  result(23, 'Fog', {
    accepted: true,
    score: 40,
    reward_kind: 'Gold',
    reward_label: 'Gold medal',
  }),
  result(24, 'Rain', {
    accepted: true,
    score: 35,
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
  await waitFor(() => expect(document.title).toBe('Nature · Rola'));
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
  renderTheme([result(25, '', { accepted: true, score: 30 })]);
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

describe('the details after an author', () => {
  function authorRowText(
    details: { school: string | null; club: string | null },
    shownContest: Contest = { ...contest, school_visible: true },
  ): Promise<string | null> {
    renderTheme(
      [
        result(21, 'Hills', {
          author: {
            ...author,
            ...details,
            reward: null,
            reward_theme: null,
            country: 'SI',
          },
        }),
      ],
      shownContest,
    );
    return screen
      .findByRole('row', { name: /^Novak, Ana/ })
      .then((row) => row.textContent);
  }

  it('shows the school and the club', async () => {
    expect(
      await authorRowText({
        school: 'Gimnazija Zgled',
        club: 'Fotoklub Okvir',
      }),
    ).toBe('Novak, Ana (Gimnazija Zgled, club: Fotoklub Okvir)');
  });

  it('shows the school alone without a club', async () => {
    expect(await authorRowText({ school: 'Gimnazija Zgled', club: null })).toBe(
      'Novak, Ana (Gimnazija Zgled)',
    );
  });

  it('shows the club alone without a school', async () => {
    expect(await authorRowText({ school: null, club: 'Fotoklub Okvir' })).toBe(
      'Novak, Ana (club: Fotoklub Okvir)',
    );
  });

  it('shows no brackets without a school or a club', async () => {
    expect(await authorRowText({ school: '', club: null })).toBe('Novak, Ana');
  });

  it('shows the country where the contest shows no schools', async () => {
    expect(
      await authorRowText({ school: 'Gimnazija Zgled', club: null }, contest),
    ).toBe('Novak, Ana (SI)');
  });
});

it('shows a failed load on a page named Results', async () => {
  document.title = 'Active contests · Rola';
  serveApi({
    'GET /contests/1': () => contest,
    'GET /results/submissions': (config) => {
      throw httpError(config, 403);
    },
  });
  renderResults('/results/contest/1/theme/2');

  await expectFailedPage(
    'Results',
    'You do not have permission to perform this action.',
  );
});

it('reports a theme that is not in the contest', async () => {
  document.title = 'Active contests · Rola';
  // The results list of such a theme is empty, like one without results.
  serveApi({
    'GET /contests/1': () => contest,
    'GET /results/submissions': () => page([]),
  });
  renderResults('/results/contest/1/theme/99');

  await expectFailedPage(
    'Results',
    'The requested content is no longer available.',
  );
});

it('reports a theme that is not in the contest when its list request fails', async () => {
  document.title = 'Active contests · Rola';
  // The API answers 400 to an id that is not a number.
  serveApi({
    'GET /contests/1': () => contest,
    'GET /results/submissions': (config) => {
      throw httpError(config, 400, { theme: ['Enter a number.'] });
    },
  });
  renderResults('/results/contest/1/theme/abc');

  await expectFailedPage(
    'Results',
    'The requested content is no longer available.',
  );
});

describe('changing the theme on the mounted page', () => {
  const [nature] = contest.themes;
  if (!nature) {
    throw new Error('The contest fixture has no theme');
  }
  const twoThemes: Contest = {
    ...contest,
    themes: [nature, { ...nature, id: 3, title: 'City' }],
  };

  // Serves both themes' lists; a theme in `held` is answered only when its
  // `release` is called.
  function serveThemes(entries: Record<string, ResultsSubmission[]>) {
    const held: Record<string, () => void> = {};
    const holding = new Set<string>();
    serveApi({
      'GET /contests/1': () => twoThemes,
      'GET /results/submissions': (_config, url) => {
        const theme = url.searchParams.get('theme') ?? '';
        const answer = page(entries[theme] ?? []);
        if (!holding.has(theme)) return answer;
        return new Promise<PaginatedResponse<ResultsSubmission>>((resolve) => {
          held[theme] = () => resolve(answer);
        });
      },
    });
    return {
      hold: (theme: string) => holding.add(theme),
      release: (theme: string) => {
        holding.delete(theme);
        held[theme]?.();
      },
    };
  }

  function renderRouter(path: string) {
    const router = createMemoryRouter(
      [
        {
          path: '/results/contest/:contestId/theme/:themeId',
          element: <ThemeResults />,
        },
      ],
      { initialEntries: [path] },
    );
    render(<RouterProvider router={router} />);
    return router;
  }

  const street = result(31, 'Street', { theme: 3 });
  const hills = result(21, 'Hills');

  it("never shows a theme's entries under another theme's title", async () => {
    const api = serveThemes({ '2': [hills], '3': [street] });
    const router = renderRouter('/results/contest/1/theme/3');
    expect(
      await screen.findByRole('heading', { level: 1, name: 'City' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Street')).toBeVisible();

    api.hold('2');
    await act(() => router.navigate('/results/contest/1/theme/2'));
    expect(screen.queryByText('Street')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { level: 1, name: 'Nature' }),
    ).not.toBeInTheDocument();

    await act(async () => api.release('2'));
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Nature' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Hills')).toBeVisible();
    expect(screen.queryByText('Street')).not.toBeInTheDocument();
  });

  it("keeps a later theme's entries when an earlier theme's list answers late", async () => {
    const api = serveThemes({ '2': [hills], '3': [street] });
    api.hold('3');
    const router = renderRouter('/results/contest/1/theme/3');
    await act(() => router.navigate('/results/contest/1/theme/2'));
    expect(await screen.findByText('Hills')).toBeVisible();

    await act(async () => api.release('3'));
    expect(screen.getByText('Hills')).toBeVisible();
    expect(screen.queryByText('Street')).not.toBeInTheDocument();
    expect(
      screen.getByRole('heading', { level: 1, name: 'Nature' }),
    ).toBeInTheDocument();
  });
});
