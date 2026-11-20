import { expect, it } from 'vitest';
import { pageRoutes, preloadPages, raterPath, uploadPath } from './routes';

// Importing every page cold transforms each page's whole module graph, which
// takes about 0.5 s on an idle machine and 1 s with two suites at once, and
// grows with the pages and the machine's load, past the default 5 s on a busy
// machine.
const preloadTimeout = 30_000;

it(
  'preloads the page of every lazily loaded route',
  async () => {
    const modules = await preloadPages();
    expect(modules).toHaveLength(pageRoutes.length);
    for (const module of modules) {
      expect(module.default).toBeTruthy();
    }
  },
  preloadTimeout,
);

it('routes each path once, the rater and the upload form among them', () => {
  const paths = pageRoutes.map(({ path }) => path);
  expect(new Set(paths).size).toBe(paths.length);
  expect(paths).toContain(raterPath);
  expect(paths).toContain(uploadPath);
});
