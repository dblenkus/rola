import type { components } from '../types/generated-api';

export type AuthToken = components['schemas']['Token'];

// The email the session was opened with names its account.
export type Session = AuthToken & { email: string };

export const sessionChanged = 'rola:session-changed';

export function loadToken(): Session | null {
  const stored = localStorage.getItem('token');
  if (!stored) {
    return null;
  }
  try {
    const value: unknown = JSON.parse(stored);
    if (
      typeof value === 'object' &&
      value !== null &&
      'token' in value &&
      typeof value.token === 'string' &&
      value.token &&
      'expires' in value &&
      typeof value.expires === 'string' &&
      Date.parse(value.expires) > Date.now() &&
      'email' in value &&
      typeof value.email === 'string' &&
      value.email
    ) {
      return { token: value.token, expires: value.expires, email: value.email };
    }
  } catch {
    // Unreadable credentials are discarded below, like expired ones.
  }
  // A removal in this tab fires no storage event, so announce it; the views
  // that need a session then send the user to the login page.
  localStorage.removeItem('token');
  window.dispatchEvent(new Event(sessionChanged));
  return null;
}

// Only the session that sent the rejected request is cleared, so a late 401
// from before a new login cannot log the user out again.
export function rejectToken(authorization: unknown): void {
  const current = loadToken();
  if (current && authorization === `Token ${current.token}`) {
    localStorage.removeItem('token');
    window.dispatchEvent(new Event(sessionChanged));
  }
}
