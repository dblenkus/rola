import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it } from 'vitest';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router';
import RouteFocus from './RouteFocus';

function Links() {
  const navigate = useNavigate();
  return (
    <>
      <button onClick={() => navigate('/plain')}>Plain</button>
      <button onClick={() => navigate('/form')}>Form</button>
      <button onClick={() => navigate('/start?page=2')}>Next page</button>
    </>
  );
}

function renderAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <RouteFocus />
      <Links />
      <main id="main" tabIndex={-1}>
        <Routes>
          <Route path="/start" element={<p>Start</p>} />
          <Route path="/plain" element={<p>Plain page</p>} />
          <Route path="/form" element={<input aria-label="Name" autoFocus />} />
        </Routes>
      </main>
    </MemoryRouter>,
  );
}

it('leaves focus alone on the first render', () => {
  renderAt('/start');
  expect(document.body).toHaveFocus();
});

it('moves focus to main after a navigation', async () => {
  const user = userEvent.setup();
  renderAt('/start');
  await user.click(screen.getByRole('button', { name: 'Plain' }));
  expect(screen.getByText('Plain page')).toBeInTheDocument();
  expect(screen.getByRole('main')).toHaveFocus();
});

it('keeps focus on a field that the new page focused', async () => {
  const user = userEvent.setup();
  renderAt('/start');
  await user.click(screen.getByRole('button', { name: 'Form' }));
  expect(screen.getByRole('textbox', { name: 'Name' })).toHaveFocus();
});

it('leaves focus alone when only the query changes', async () => {
  const user = userEvent.setup();
  renderAt('/start');
  const next = screen.getByRole('button', { name: 'Next page' });
  await user.click(next);
  expect(next).toHaveFocus();
});
