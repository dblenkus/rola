import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it } from 'vitest';
import { httpError, serveApi } from '../../../test/api';
import PasswordReset from './PasswordReset';

function renderReset() {
  return render(
    <MemoryRouter initialEntries={['/password-reset?token=signed-token']}>
      <Routes>
        <Route path="/password-reset" element={<PasswordReset />} />
        <Route path="/login" element={<p>Login page</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

it('asks for a new password on a titled page', () => {
  renderReset();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(document.title).toBe('Password reset · Rola');
  const password = screen.getByLabelText(/^New password/);
  expect(password).toHaveAttribute('type', 'password');
  expect(password).toHaveAttribute('autocomplete', 'new-password');
  expect(password).toBeRequired();
});

it('shows a rejected password on the field', async () => {
  serveApi({
    'POST /user/password_reset': (config) => {
      throw httpError(config, 400, {
        new_password: ['This password is too common.'],
      });
    },
  });
  const user = userEvent.setup();
  renderReset();
  await user.type(screen.getByLabelText(/^New password/), 'password123');
  await user.click(screen.getByRole('button', { name: 'Password reset' }));

  expect(
    await screen.findByText('This password is too common.'),
  ).toBeInTheDocument();
  const password = screen.getByLabelText(/^New password/);
  expect(password).toHaveAttribute('aria-invalid', 'true');
  expect(password).toHaveAccessibleDescription('This password is too common.');
});

it('offers the way to login after a successful reset', async () => {
  serveApi({ 'POST /user/password_reset': () => ({}) });
  const user = userEvent.setup();
  renderReset();
  await user.type(screen.getByLabelText(/^New password/), 'Replacement!73');
  await user.click(screen.getByRole('button', { name: 'Password reset' }));

  expect(
    await screen.findByRole('heading', {
      level: 2,
      name: 'Password was successfully reset!',
    }),
  ).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Go to Log in' }));
  expect(await screen.findByText('Login page')).toBeInTheDocument();
});
