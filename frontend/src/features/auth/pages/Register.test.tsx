import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { expect, it } from 'vitest';
import { httpError, serveApi } from '../../../test/api';
import Register from './Register';

function renderRegister() {
  return render(
    <MemoryRouter initialEntries={['/register']}>
      <Register />
    </MemoryRouter>,
  );
}

it('titles the page and renders no MUI markup', () => {
  const { container } = renderRegister();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(
    screen.getByRole('heading', { level: 1, name: 'Register' }),
  ).toBeInTheDocument();
  expect(document.title).toBe('Register · Rola');
  expect(container.querySelector('[class*="Mui"]')).toBeNull();
  expect(
    screen.getByRole('link', { name: 'Already have an account? Log in' }),
  ).toHaveAttribute('href', '/login');
});

it('gives every field the attributes autofill and keyboards need', () => {
  renderRegister();
  const textbox = (name: string) => screen.getByRole('textbox', { name });
  expect(textbox('First name')).toHaveAttribute('autocomplete', 'given-name');
  expect(textbox('First name')).toHaveFocus();
  expect(textbox('Last name')).toHaveAttribute('autocomplete', 'family-name');
  expect(textbox('Email')).toHaveAttribute('type', 'email');
  expect(textbox('Email')).toHaveAttribute('autocomplete', 'email');
  expect(textbox('Email')).toHaveAttribute('inputmode', 'email');
  expect(screen.getByLabelText(/^Password/)).toHaveAttribute(
    'type',
    'password',
  );
  expect(screen.getByLabelText(/^Password/)).toHaveAttribute(
    'autocomplete',
    'new-password',
  );
  expect(textbox('Address')).toHaveAttribute('autocomplete', 'street-address');
  expect(textbox('City')).toHaveAttribute('autocomplete', 'address-level2');
  // Foreign postal codes have letters, so the keyboard is not numeric.
  expect(textbox('Postal code')).toHaveAttribute('type', 'text');
  expect(textbox('Postal code')).toHaveAttribute('inputmode', 'text');
  expect(textbox('Postal code')).toHaveAttribute('autocomplete', 'postal-code');
  expect(textbox('Country')).toHaveAttribute('autocomplete', 'country-name');
  for (const field of [
    'First name',
    'Last name',
    'Email',
    'Address',
    'City',
    'Postal code',
    'Country',
  ]) {
    expect(textbox(field)).toBeRequired();
  }
});

it('puts each server error on its field', async () => {
  serveApi({
    'POST /user': (config) => {
      throw httpError(config, 400, {
        email: ['A user with that email already exists.'],
      });
    },
  });
  const user = userEvent.setup();
  renderRegister();
  const values: Record<string, string> = {
    'First name': 'Ana',
    'Last name': 'Novak',
    Email: 'ana@example.com',
    Address: 'Trubarjeva 1',
    City: 'Ljubljana',
    'Postal code': '1000',
    Country: 'Slovenia',
  };
  for (const [name, value] of Object.entries(values)) {
    await user.type(screen.getByRole('textbox', { name }), value);
  }
  await user.type(screen.getByLabelText(/^Password/), 'Example!73');
  await user.click(screen.getByRole('button', { name: 'Register' }));

  const email = screen.getByRole('textbox', { name: 'Email' });
  expect(
    await screen.findByText('A user with that email already exists.'),
  ).toBeInTheDocument();
  expect(email).toHaveAttribute('aria-invalid', 'true');
  expect(email).toHaveAccessibleDescription(
    'A user with that email already exists.',
  );
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('confirms the registration with the address it was sent to', async () => {
  serveApi({ 'POST /user': () => ({}) });
  const user = userEvent.setup();
  renderRegister();
  const values: Record<string, string> = {
    'First name': 'Ana',
    'Last name': 'Novak',
    Email: 'ana@example.com',
    Address: 'Trubarjeva 1',
    City: 'Ljubljana',
    'Postal code': 'SW1A 1AA',
    Country: 'United Kingdom',
  };
  for (const [name, value] of Object.entries(values)) {
    await user.type(screen.getByRole('textbox', { name }), value);
  }
  await user.type(screen.getByLabelText(/^Password/), 'Example!73');
  await user.click(screen.getByRole('button', { name: 'Register' }));

  expect(
    await screen.findByRole('heading', {
      level: 2,
      name: 'Thank you for the registration!',
    }),
  ).toBeInTheDocument();
  expect(
    screen.getByText(/sent you to your ana@example\.com email address/),
  ).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
});
