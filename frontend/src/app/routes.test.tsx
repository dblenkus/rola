import { expect, it } from 'vitest';
import { pageRoutes, preloadPages, raterPath, uploadPath } from './routes';

it('preloads the page of every lazily loaded route', async () => {
  const modules = await preloadPages();
  expect(modules).toHaveLength(pageRoutes.length);
  for (const module of modules) {
    expect(module.default).toBeTruthy();
  }
});

it('routes each path once, the rater and the upload form among them', () => {
  const paths = pageRoutes.map(({ path }) => path);
  expect(new Set(paths).size).toBe(paths.length);
  expect(paths).toContain(raterPath);
  expect(paths).toContain(uploadPath);
});
