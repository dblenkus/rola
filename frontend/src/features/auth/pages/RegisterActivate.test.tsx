import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import { serveApi } from '../../../test/api';
import RegisterActivate from './RegisterActivate';

function renderActivate(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/register/activate" element={<RegisterActivate />} />
        <Route path="/login" element={<p>Login page</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

it('reports an activated account and offers the way to login', async () => {
  serveApi({ 'POST /user/activate_account': () => ({}) });
  const user = userEvent.setup();
  renderActivate('/register/activate?token=signed');

  expect(
    await screen.findByRole('heading', {
      level: 2,
      name: 'Your account is now active!',
    }),
  ).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  await waitFor(() => expect(document.title).toBe('Acount activation · Rola'));
  await user.click(screen.getByRole('button', { name: 'Go to Login' }));
  expect(await screen.findByText('Login page')).toBeInTheDocument();
});

it('explains a missing token under a heading', async () => {
  renderActivate('/register/activate');
  expect(
    await screen.findByRole('heading', {
      level: 2,
      name: 'Account activation failed!',
    }),
  ).toBeInTheDocument();
  expect(screen.getByText('Invalid token.')).toBeInTheDocument();
});
