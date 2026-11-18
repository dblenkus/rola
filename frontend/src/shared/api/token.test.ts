import { beforeEach, describe, expect, it, vi } from 'vitest';
import { blockStorage } from '../../test/api';
import { loadToken, rejectToken, sessionChanged } from './token';

beforeEach(() => localStorage.clear());

describe('persisted authentication', () => {
  it('keeps a token until its actual expiry', () => {
    const token = {
      token: 'test-token',
      expires: new Date(Date.now() + 60_000).toISOString(),
      email: 'ana@example.com',
    };
    localStorage.setItem('token', JSON.stringify(token));
    expect(loadToken()).toEqual(token);
  });

  it.each([
    'not json',
    '{}',
    JSON.stringify({ token: 123, expires: '2999-01-01' }),
    JSON.stringify({ token: '', expires: '2999-01-01' }),
    JSON.stringify({ token: 'expired', expires: '2000-01-01' }),
    JSON.stringify({ token: 'invalid', expires: 'never' }),
    JSON.stringify({ token: 'no-account', expires: '2999-01-01' }),
  ])('discards invalid or expired credentials: %s', (stored) => {
    const announced = vi.fn();
    window.addEventListener(sessionChanged, announced);
    localStorage.setItem('token', stored);
    expect(loadToken()).toBeNull();
    expect(localStorage.getItem('token')).toBeNull();
    window.removeEventListener(sessionChanged, announced);
    expect(announced).toHaveBeenCalledOnce();
  });

  it('announces nothing when no session is stored', () => {
    const announced = vi.fn();
    window.addEventListener(sessionChanged, announced);
    expect(loadToken()).toBeNull();
    window.removeEventListener(sessionChanged, announced);
    expect(announced).not.toHaveBeenCalled();
  });

  it('finds no session when site storage is blocked', () => {
    const announced = vi.fn();
    window.addEventListener(sessionChanged, announced);
    blockStorage();
    expect(loadToken()).toBeNull();
    window.removeEventListener(sessionChanged, announced);
    expect(announced).not.toHaveBeenCalled();
  });
});

describe('rejected sessions', () => {
  it('clears the session that sent the rejected request', () => {
    localStorage.setItem(
      'token',
      JSON.stringify({
        token: 'current',
        expires: '2999-01-01',
        email: 'ana@example.com',
      }),
    );
    rejectToken('Token current');
    expect(loadToken()).toBeNull();
  });

  it('keeps a newer login when an older request is rejected', () => {
    const token = {
      token: 'new-session',
      expires: '2999-01-01',
      email: 'ana@example.com',
    };
    localStorage.setItem('token', JSON.stringify(token));
    rejectToken('Token old-session');
    expect(loadToken()).toEqual(token);
  });
});
