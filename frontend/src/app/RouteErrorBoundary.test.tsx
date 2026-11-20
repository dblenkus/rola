import { lazy, Suspense } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { Link, MemoryRouter, Route, Routes } from 'react-router';
import RouteErrorBoundary from './RouteErrorBoundary';

function Broken(): never {
  throw new Error('The page failed');
}

const MissingChunk = lazy(() =>
  Promise.reject(new TypeError('Failed to fetch dynamically imported module')),
);

function renderAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <nav>
        <Link to="/fine">Fine</Link>
      </nav>
      <RouteErrorBoundary>
        <Suspense fallback={<p>Loading</p>}>
          <Routes>
            <Route path="/broken" element={<Broken />} />
            <Route path="/missing" element={<MissingChunk />} />
            <Route path="/fine" element={<p>Fine page</p>} />
          </Routes>
        </Suspense>
      </RouteErrorBoundary>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  // React logs every error that a boundary catches.
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

it('shows the error page instead of a page that fails to render', () => {
  renderAt('/broken');
  expect(
    screen.getByRole('heading', { level: 1, name: 'Something went wrong' }),
  ).toBeInTheDocument();
  expect(
    screen.getByText('This page could not be shown. Reload it to try again.'),
  ).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Fine' })).toBeInTheDocument();
});

it('shows the error page when a page fails to load', async () => {
  renderAt('/missing');
  expect(
    await screen.findByRole('heading', { name: 'Something went wrong' }),
  ).toBeInTheDocument();
});

it('shows the next page after a navigation', async () => {
  const user = userEvent.setup();
  renderAt('/broken');
  await user.click(screen.getByRole('link', { name: 'Fine' }));
  expect(await screen.findByText('Fine page')).toBeInTheDocument();
  expect(
    screen.queryByRole('heading', { name: 'Something went wrong' }),
  ).not.toBeInTheDocument();
});
