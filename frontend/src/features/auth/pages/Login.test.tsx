import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { beforeEach, expect, it } from 'vitest';
import { httpError, serveApi } from '../../../test/api';
import AuthProvider from '../components/AuthProvider';
import Login from './Login';

beforeEach(() => {
  localStorage.clear();
});

function renderLogin() {
  return render(
    <MemoryRouter initialEntries={['/login']}>
      <AuthProvider>
        <Login />
      </AuthProvider>
    </MemoryRouter>,
  );
}

it('titles the page', () => {
  renderLogin();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(
    screen.getByRole('heading', { level: 1, name: 'Login' }),
  ).toBeInTheDocument();
  expect(document.title).toBe('Login · Rola');
});

it('asks for the email and the current password', () => {
  renderLogin();
  const email = screen.getByRole('textbox', { name: 'Email' });
  expect(email).toHaveAttribute('type', 'email');
  expect(email).toHaveAttribute('autocomplete', 'email');
  expect(email).toHaveAttribute('inputmode', 'email');
  expect(email).toBeRequired();
  expect(email).toHaveFocus();
  const password = screen.getByLabelText(/^Password/);
  expect(password).toHaveAttribute('type', 'password');
  expect(password).toHaveAttribute('autocomplete', 'current-password');
  expect(password).toBeRequired();
});

it('links to the password reset and registration as full tap targets', () => {
  renderLogin();
  expect(
    screen.getByRole('link', { name: 'Forgot password?' }),
  ).toHaveAttribute('href', '/password-reset/request');
  expect(
    screen.getByRole('link', { name: "Don't have an account? Register" }),
  ).toHaveAttribute('href', '/register');
  for (const link of screen.getAllByRole('link')) {
    expect(link).toHaveClass('auth-links__link');
  }
});

it('shows field errors on their fields and the rest as an alert', async () => {
  serveApi({
    'POST /user/login': (config) => {
      throw httpError(config, 400, {
        password: ['This field may not be blank.'],
        non_field_errors: ['Unable to log in with provided credentials.'],
      });
    },
  });
  const user = userEvent.setup();
  renderLogin();
  await user.type(
    screen.getByRole('textbox', { name: 'Email' }),
    'ana@example.com',
  );
  await user.type(screen.getByLabelText(/^Password/), 'wrong-password');
  await user.click(screen.getByRole('button', { name: 'Login' }));

  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Unable to log in with provided credentials.',
  );
  const password = screen.getByLabelText(/^Password/);
  expect(password).toHaveAttribute('aria-invalid', 'true');
  expect(password).toHaveAccessibleDescription('This field may not be blank.');
  expect(screen.getByRole('textbox', { name: 'Email' })).not.toHaveAttribute(
    'aria-invalid',
  );
});

it('lets the browser refuse an email address without an @', async () => {
  const adapter = serveApi({});
  const user = userEvent.setup();
  renderLogin();
  await user.type(screen.getByRole('textbox', { name: 'Email' }), 'ana');
  await user.type(screen.getByLabelText(/^Password/), 'example-password');
  await user.click(screen.getByRole('button', { name: 'Login' }));
  expect(screen.getByRole('textbox', { name: 'Email' })).toBeInvalid();
  expect(adapter).not.toHaveBeenCalled();
});
