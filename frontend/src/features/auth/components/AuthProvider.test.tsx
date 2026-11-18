import { useContext } from 'react';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadToken } from '../../../shared/api/token';
import { blockStorage, serveApi } from '../../../test/api';
import AuthProvider, { userContext } from './AuthProvider';
import PrivateRoute from './PrivateRoute';

const token = { token: 'example-token', expires: '2999-01-01T00:00:00Z' };
const session = { ...token, email: 'user@example.com' };

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

function Session() {
  const auth = useContext(userContext);
  return (
    <>
      <span>{auth.isLoggedIn() ? 'Signed in' : 'Signed out'}</span>
      <button
        onClick={() =>
          auth.login({ email: ' User@Example.com', password: 'example' })
        }
      >
        Log in
      </button>
      <button onClick={auth.logout}>Log out</button>
    </>
  );
}

function Destination() {
  const location = useLocation();
  return <p>{location.state?.from?.pathname}</p>;
}

describe('authentication flows', () => {
  it('stores a login and clears it on logout', async () => {
    serveApi({ 'POST /user/login': () => token });
    const user = userEvent.setup();
    render(
      <AuthProvider>
        <Session />
      </AuthProvider>,
    );
    await user.click(screen.getByRole('button', { name: 'Log in' }));
    expect(await screen.findByText('Signed in')).toBeInTheDocument();
    expect(JSON.parse(localStorage.getItem('token') ?? 'null')).toEqual(
      session,
    );
    await user.click(screen.getByRole('button', { name: 'Log out' }));
    expect(screen.getByText('Signed out')).toBeInTheDocument();
    expect(localStorage.getItem('token')).toBeNull();
  });

  it('signs out when a request finds the session expired', () => {
    const now = Date.now();
    localStorage.setItem(
      'token',
      JSON.stringify({
        token: 'expiring',
        expires: new Date(now + 60_000).toISOString(),
        email: 'user@example.com',
      }),
    );
    render(
      <AuthProvider>
        <Session />
      </AuthProvider>,
    );
    expect(screen.getByText('Signed in')).toBeInTheDocument();
    vi.spyOn(Date, 'now').mockReturnValue(now + 120_000);
    // The API client reads the session before every request.
    act(() => {
      loadToken();
    });
    expect(screen.getByText('Signed out')).toBeInTheDocument();
  });

  it('logs out after site storage is blocked during a session', async () => {
    localStorage.setItem('token', JSON.stringify(session));
    const user = userEvent.setup();
    render(
      <AuthProvider>
        <Session />
      </AuthProvider>,
    );
    expect(screen.getByText('Signed in')).toBeInTheDocument();
    blockStorage();
    await user.click(screen.getByRole('button', { name: 'Log out' }));
    expect(screen.getByText('Signed out')).toBeInTheDocument();
  });

  it('follows a logout in another tab', () => {
    localStorage.setItem('token', JSON.stringify(session));
    render(
      <AuthProvider>
        <Session />
      </AuthProvider>,
    );
    expect(screen.getByText('Signed in')).toBeInTheDocument();
    localStorage.removeItem('token');
    act(() => {
      window.dispatchEvent(new StorageEvent('storage', { key: 'token' }));
    });
    expect(screen.getByText('Signed out')).toBeInTheDocument();
  });

  it('preserves the requested path when redirecting to login', () => {
    render(
      <AuthProvider>
        <MemoryRouter initialEntries={['/contest/1/upload']}>
          <Routes>
            <Route
              path="/contest/:id/upload"
              element={
                <PrivateRoute>
                  <p>Private content</p>
                </PrivateRoute>
              }
            />
            <Route path="/login" element={<Destination />} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>,
    );
    expect(screen.getByText('/contest/1/upload')).toBeInTheDocument();
    expect(screen.queryByText('Private content')).not.toBeInTheDocument();
  });
});
