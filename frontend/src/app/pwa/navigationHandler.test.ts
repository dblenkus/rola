import { describe, expect, it, vi } from 'vitest';

import { answerNavigation, handlesNavigation } from './navigationHandler';

const ORIGIN = 'https://rola.test';

function navigation(path: string) {
  return new Request(new URL(path, ORIGIN));
}

function shell() {
  return new Response('<!doctype html><title>Rola</title>', {
    headers: { 'Content-Type': 'text/html' },
  });
}

describe('handlesNavigation', () => {
  it.each(['/', '/contests', '/contest/3/details?tab=themes', '/index.html'])(
    'handles a navigation to %s',
    (path) => {
      expect(
        handlesNavigation({ mode: 'navigate' }, new URL(path, ORIGIN)),
      ).toBe(true);
    },
  );

  it.each([
    '/api/v1/contests',
    '/django-admin/',
    '/media/photos/a.jpg',
    '/static2/x.css',
    '/assets/index-abc.js',
    '/sw.js',
  ])('never handles a navigation to the server path %s', (path) => {
    expect(handlesNavigation({ mode: 'navigate' }, new URL(path, ORIGIN))).toBe(
      false,
    );
  });

  it.each<RequestMode>(['cors', 'no-cors', 'same-origin'])(
    'does not handle a %s request',
    (mode) => {
      expect(handlesNavigation({ mode }, new URL('/contests', ORIGIN))).toBe(
        false,
      );
    },
  );
});

describe('answerNavigation', () => {
  it('answers with the network response', async () => {
    const response = new Response('page', { status: 200 });
    const request = navigation('/contests');
    const fetch = vi.fn(() => Promise.resolve(response));
    const precachedShell = vi.fn(() => Promise.resolve(shell()));

    const answer = await answerNavigation(request, { fetch, precachedShell });

    expect(answer).toBe(response);
    expect(fetch).toHaveBeenCalledExactlyOnceWith(request);
    expect(precachedShell).not.toHaveBeenCalled();
  });

  it('passes a server error through unchanged', async () => {
    const response = new Response('Bad gateway', { status: 502 });

    const answer = await answerNavigation(navigation('/'), {
      fetch: () => Promise.resolve(response),
      precachedShell: () => Promise.resolve(shell()),
    });

    expect(answer).toBe(response);
  });

  it('answers with the precached shell when the network cannot be reached', async () => {
    const stored = shell();

    const answer = await answerNavigation(navigation('/contests'), {
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      precachedShell: () => Promise.resolve(stored),
    });

    expect(answer).toBe(stored);
  });

  it('answers with an error when neither the network nor the shell is there', async () => {
    const answer = await answerNavigation(navigation('/contests'), {
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      precachedShell: () => Promise.resolve(undefined),
    });

    expect(answer.type).toBe('error');
    expect(answer.status).toBe(0);
  });
});
