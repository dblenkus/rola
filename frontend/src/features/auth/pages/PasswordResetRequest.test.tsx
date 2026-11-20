import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { expect, it } from 'vitest';
import PasswordResetRequest from './PasswordResetRequest';

it('asks for the email on a titled page', () => {
  render(
    <MemoryRouter>
      <PasswordResetRequest />
    </MemoryRouter>,
  );
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(document.title).toBe('Password reset · Rola');
  const email = screen.getByRole('textbox', { name: 'Email' });
  expect(email).toHaveAttribute('type', 'email');
  expect(email).toHaveAttribute('autocomplete', 'email');
  expect(email).toHaveAttribute('inputmode', 'email');
  expect(email).toBeRequired();
  expect(email).toHaveFocus();
  expect(
    screen.getByRole('button', { name: 'Request Password Reset' }),
  ).toHaveAttribute('type', 'submit');
});
