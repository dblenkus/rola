import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import { page, serveApi } from '../../../test/api';
import { contest, submissionSet } from '../../../test/fixtures';
import type { Payment, SubmissionSet } from '../../../shared/api/types';
import SubmissionSetList from './SubmissionSetList';

function sets(count: number): SubmissionSet[] {
  return Array.from({ length: count }, (_, index) => ({
    ...submissionSet,
    id: index + 1,
    author: { ...submissionSet.author, first_name: `Ana${index + 1}` },
  }));
}

function payment(submissionSetId: number, paid: boolean): Payment {
  return {
    id: 100 + submissionSetId,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    submissionset: submissionSetId,
    paid,
  };
}

function serveSets(all: SubmissionSet[], payments: Payment[] = []) {
  return serveApi({
    'GET /contest/1': () => contest,
    'GET /submissionset': (config) => {
      const pageNumber: number = config.params.page;
      const pageSize: number = config.params.page_size;
      return {
        ...page(all.slice((pageNumber - 1) * pageSize, pageNumber * pageSize)),
        count: all.length,
      };
    },
    'GET /payment': () => page(payments),
  });
}

function renderList(): void {
  render(
    <MemoryRouter initialEntries={['/admin/contest/1/submissions']}>
      <Routes>
        <Route
          path="/admin/contest/:contestId/submissions"
          element={<SubmissionSetList />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

it('titles the page with the contest', async () => {
  serveSets(sets(1));
  renderList();

  expect(
    await screen.findByRole('heading', { level: 1, name: contest.title }),
  ).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  await waitFor(() => expect(document.title).toBe(`${contest.title} · Rola`));
  expect(document.querySelector('[class*="Mui"]')).toBeNull();
});

it('names each paid checkbox after its author and shows its state', async () => {
  serveSets(sets(2), [payment(1, true)]);
  renderList();

  const paid = await screen.findByRole('checkbox', {
    name: 'Paid: Ana1 Novak',
  });
  await waitFor(() => expect(paid).toBeChecked());
  const unpaid = screen.getByRole('checkbox', { name: 'Paid: Ana2 Novak' });
  expect(unpaid).not.toBeChecked();

  // On phones the cell's label says the state in words.
  expect(paid.closest('td')).toHaveAttribute('data-label', 'Paid');
  expect(unpaid.closest('td')).toHaveAttribute('data-label', 'Not paid');
});

it('labels each cell with its column for the phone layout', async () => {
  serveSets(sets(1));
  renderList();

  const row = (await screen.findByRole('rowheader', { name: 'Ana1 Novak' }))
    .parentElement;
  if (!row) {
    throw new Error('The author cell has no row');
  }
  const labels = [
    ...within(row).getAllByRole('rowheader'),
    ...within(row).getAllByRole('cell'),
  ].map((cell) => cell.getAttribute('data-label'));
  expect(labels).toEqual([
    'Name',
    'Submited',
    'Number of themes',
    'Number of submissons',
    'Not paid',
    null,
  ]);
  expect(within(row).getByRole('link', { name: 'View' })).toHaveAttribute(
    'href',
    '/admin/contest/1/submission/1',
  );
  expect(
    within(row).getByRole('button', { name: 'Delete' }),
  ).toBeInTheDocument();
});

it('moves to the next page and back', async () => {
  serveSets(sets(21));
  const user = userEvent.setup();
  renderList();

  expect(await screen.findByText('1-20 of 21')).toBeInTheDocument();
  expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(20);

  await user.click(screen.getByRole('button', { name: 'Go to next page' }));
  expect(await screen.findByText('21-21 of 21')).toBeInTheDocument();
  expect(
    screen.getByRole('rowheader', { name: 'Ana21 Novak' }),
  ).toBeInTheDocument();
  expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(1);

  await user.click(screen.getByRole('button', { name: 'Go to previous page' }));
  expect(await screen.findByText('1-20 of 21')).toBeInTheDocument();
});

it('requests the chosen number of rows from the first page', async () => {
  const adapter = serveSets(sets(21));
  const user = userEvent.setup();
  renderList();

  await user.click(
    await screen.findByRole('button', { name: 'Go to next page' }),
  );
  expect(await screen.findByText('21-21 of 21')).toBeInTheDocument();

  await user.selectOptions(
    screen.getByRole('combobox', { name: 'Rows per page:' }),
    '50',
  );
  expect(await screen.findByText('1-21 of 21')).toBeInTheDocument();
  expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(21);
  const lastList = adapter.mock.calls
    .map(([config]) => config)
    .filter(({ url }) => url === '/submissionset')
    .at(-1);
  expect(lastList?.params).toMatchObject({ page: 1, page_size: 50 });
});
