import { render, screen, within, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import { serveApi } from '../../../test/api';
import { contest } from '../../../test/fixtures';
import SelectTheme from './SelectTheme';

it('lists the contest themes with a link to each one', async () => {
  serveApi({ 'GET /contest/1': () => contest });
  render(
    <MemoryRouter initialEntries={['/results/contest/1']}>
      <Routes>
        <Route path="/results/contest/:contestId" element={<SelectTheme />} />
      </Routes>
    </MemoryRouter>,
  );

  expect(
    await screen.findByRole('heading', {
      level: 1,
      name: 'Autumn photographs',
    }),
  ).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  await waitFor(() => expect(document.title).toBe('Autumn photographs · Rola'));

  const rows = screen.getAllByRole('row');
  expect(rows.map((row) => row.textContent)).toEqual(['NatureView']);
  const [nature] = rows;
  if (!nature) {
    throw new Error('No theme row');
  }
  expect(
    within(nature).getByRole('link', { name: 'View Nature' }),
  ).toHaveAttribute('href', '/results/contest/1/theme/2');
  expect(document.querySelector('[class*="Mui"]')).toBeNull();
});
