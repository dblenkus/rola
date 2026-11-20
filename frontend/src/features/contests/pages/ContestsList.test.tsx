import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import { page, serveApi } from '../../../test/api';
import { contest } from '../../../test/fixtures';
import ContestsList from './ContestsList';

describe('contests list', () => {
  it('lists the active contests as rows under the page title', async () => {
    serveApi({
      'GET /contests': () =>
        page([contest, { ...contest, id: 3, title: 'Winter photographs' }]),
    });
    render(
      <MemoryRouter>
        <ContestsList />
      </MemoryRouter>,
    );
    const list = await screen.findByRole('list');
    expect(
      within(list)
        .getAllByRole('listitem')
        .map(
          (item) => within(item).getByRole('heading', { level: 2 }).textContent,
        ),
    ).toEqual([contest.title, 'Winter photographs']);
    expect(
      screen.getByRole('heading', { level: 1, name: 'Active contests' }),
    ).toBeInTheDocument();
    expect(document.title).toBe('Active contests · Rola');
  });
});
