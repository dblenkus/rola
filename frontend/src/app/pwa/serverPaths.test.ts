import { describe, expect, it } from 'vitest';

import { isServerPath } from './serverPaths';

describe('isServerPath', () => {
  it.each([
    '/api/v1/contests',
    '/api',
    '/api?page=2',
    '/django-admin/',
    '/django-admin',
    '/media/photos/a.jpg',
    '/static2/x.css',
    '/assets/index-abc.js',
    '/sw.js',
    '/site.webmanifest',
    '/favicon.ico',
    '/manifest.json?v=1',
  ])('leaves %s to the server', (path) => {
    expect(isServerPath(path)).toBe(true);
  });

  it.each([
    '/',
    '/contests',
    '/contest/3/details',
    '/results/contest/1/theme/2?x=a.b',
    '/contest/3.5/details',
    '/apiary',
    '/mediation',
    '/assetsx',
  ])('serves the app for %s', (path) => {
    expect(isServerPath(path)).toBe(false);
  });
});
