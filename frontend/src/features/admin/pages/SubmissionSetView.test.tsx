import { act, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import { httpError, serveApi } from '../../../test/api';
import { expectFailedPage } from '../../../test/pages';
import { contest, submission, submissionSet } from '../../../test/fixtures';
import type { SubmissionSet } from '../../../shared/api/types';
import SubmissionSetView from './SubmissionSetView';

function renderView(): void {
  render(
    <MemoryRouter initialEntries={['/admin/contest/1/submission/5']}>
      <Routes>
        <Route
          path="/admin/contest/:contestId/submission/:submissionSetId"
          element={<SubmissionSetView />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

function serveSet(data: SubmissionSet): void {
  serveApi({
    'GET /contest/1': () => contest,
    'GET /submissionset/5': () => data,
  });
}

function definitions(list: HTMLElement): Record<string, string> {
  const terms = within(list).getAllByRole('term');
  return Object.fromEntries(
    terms.map((term) => [
      term.textContent,
      term.nextElementSibling?.textContent ?? '',
    ]),
  );
}

it('shows loading until the set arrives', async () => {
  let answer: (() => void) | undefined;
  serveApi({
    'GET /contest/1': () => contest,
    'GET /submissionset/5': () =>
      new Promise((resolve) => {
        answer = () => resolve(submissionSet);
      }),
  });
  renderView();

  expect(screen.getByRole('progressbar')).toBeInTheDocument();
  // Until the author is known the page has its generic heading.
  expect(
    screen.getByRole('heading', { level: 1, name: 'Submission' }),
  ).toBeInTheDocument();

  await waitFor(() => expect(answer).toBeDefined());
  expect(screen.getByRole('progressbar')).toBeInTheDocument();
  await act(async () => answer?.());
  expect(
    await screen.findByRole('heading', { level: 1, name: 'Ana Novak' }),
  ).toBeInTheDocument();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
});

it('titles the page with the author and lists the details', async () => {
  serveSet({
    ...submissionSet,
    author: { ...submissionSet.author, email: 'ana@example.com' },
  });
  renderView();

  await screen.findByRole('heading', { level: 1, name: 'Ana Novak' });
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  await waitFor(() => expect(document.title).toBe('Ana Novak · Rola'));
  const details = screen.getAllByRole('definition')[0]?.closest('dl');
  if (!(details instanceof HTMLElement)) {
    throw new Error('The page has no definition list');
  }
  expect(definitions(details)).toEqual({
    Contest: contest.title,
    Author: 'Ana Novak',
    Email: 'ana@example.com',
  });
});

it('shows each photograph as a linked thumbnail with its details', async () => {
  const [photo] = submission(11, 'Autumn trees').files;
  if (!photo) {
    throw new Error('The fixture has no photograph');
  }
  serveSet({
    ...submissionSet,
    submissions: [
      {
        ...submission(11, 'Autumn trees'),
        description: 'Leaves in the wind.',
        files: [{ ...photo, thumbnail: 'https://media.example/11-small.jpg' }],
      },
    ],
  });
  renderView();

  const image = await screen.findByRole('img', { name: 'Autumn trees' });
  expect(image).toHaveAttribute('src', 'https://media.example/11-small.jpg');
  expect(image).toHaveAttribute('loading', 'lazy');
  expect(image).toHaveAttribute('decoding', 'async');
  const link = screen.getByRole('link', { name: 'Autumn trees' });
  expect(link).toHaveAttribute('href', 'https://media.example/11.jpg');
  expect(link).toHaveAttribute('target', '_blank');
  expect(link).toHaveAttribute('rel', 'noopener noreferrer');

  const figure = screen.getByRole('figure');
  const caption = figure.querySelector('figcaption');
  if (!(caption instanceof HTMLElement)) {
    throw new Error('The photograph has no caption');
  }
  expect(definitions(caption)).toEqual({
    Title: 'Autumn trees',
    Theme: 'Nature',
    Description: 'Leaves in the wind.',
  });
});

it('names an untitled photograph and uses the file without a thumbnail', async () => {
  serveSet({
    ...submissionSet,
    submissions: [{ ...submission(11, ''), title: null }],
  });
  renderView();

  const image = await screen.findByRole('img', {
    name: 'Untitled photograph',
  });
  expect(image).toHaveAttribute('src', 'https://media.example/11.jpg');
  expect(
    screen.getByRole('link', { name: 'Untitled photograph' }),
  ).toBeInTheDocument();
});

it('numbers the photographs of a series', async () => {
  serveSet({
    ...submissionSet,
    submissions: [
      {
        ...submission(11, 'Bridges'),
        files: [11, 12].flatMap((id) => submission(id, '').files),
      },
    ],
  });
  renderView();

  expect(
    await screen.findByRole('link', { name: 'Bridges, photo 1 of 2' }),
  ).toHaveAttribute('href', 'https://media.example/11.jpg');
  expect(
    screen.getByRole('link', { name: 'Bridges, photo 2 of 2' }),
  ).toHaveAttribute('href', 'https://media.example/12.jpg');
});

it('shows a failed load on a page named Submission', async () => {
  document.title = 'Active contests · Rola';
  serveApi({
    'GET /contest/1': () => contest,
    'GET /submissionset/5': (config) => {
      throw httpError(config, 404);
    },
  });
  renderView();

  await expectFailedPage(
    'Submission',
    'The requested content is no longer available.',
  );
});
