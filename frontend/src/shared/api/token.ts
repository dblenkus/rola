import type { components } from './generated-api';

export type AuthToken = components['schemas']['Token'];

// The email the session was opened with names its account.
export type Session = AuthToken & { email: string };

export const sessionChanged = 'rola:session-changed';

// Thrown when the browser refuses to store a new login. The API client reads
// the session from site storage, so a session kept only in memory would send
// requests without its token.
export class StorageBlocked extends Error {
  constructor(options?: ErrorOptions) {
    super('Site storage is blocked', options);
    this.name = 'StorageBlocked';
  }
}

// A browser that blocks site data for the site throws on every access to its
// storage, which then holds no session: public pages work without one.
function readStored(): string | null {
  try {
    return localStorage.getItem('token');
  } catch {
    return null;
  }
}

export function removeStored(): void {
  try {
    localStorage.removeItem('token');
  } catch {
    // Blocked storage keeps no session to remove.
  }
}

export function loadToken(): Session | null {
  const stored = readStored();
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
  removeStored();
  window.dispatchEvent(new Event(sessionChanged));
  return null;
}

// Only the session that sent the rejected request is cleared, so a late 401
// from before a new login cannot log the user out again.
export function rejectToken(authorization: unknown): void {
  const current = loadToken();
  if (current && authorization === `Token ${current.token}`) {
    removeStored();
    window.dispatchEvent(new Event(sessionChanged));
  }
}
