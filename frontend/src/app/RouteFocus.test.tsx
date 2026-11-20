import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import {
  MemoryRouter,
  Navigate,
  Route,
  Routes,
  useNavigate,
} from 'react-router';
import RouteFocus from './RouteFocus';

function Links() {
  const navigate = useNavigate();
  return (
    <>
      <button onClick={() => navigate('/plain')}>Plain</button>
      <button onClick={() => navigate('/form')}>Form</button>
      <button onClick={() => navigate('/start?page=2')}>Next page</button>
    </>
  );
}

function renderAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <RouteFocus />
      <Links />
      <main id="main" tabIndex={-1}>
        <Routes>
          <Route path="/start" element={<p>Start</p>} />
          <Route path="/plain" element={<p>Plain page</p>} />
          <Route path="/form" element={<input aria-label="Name" autoFocus />} />
        </Routes>
      </main>
    </MemoryRouter>,
  );
}

it('leaves focus alone on the first render', () => {
  renderAt('/start');
  expect(document.body).toHaveFocus();
});

it('moves focus to main after a navigation', async () => {
  const user = userEvent.setup();
  renderAt('/start');
  await user.click(screen.getByRole('button', { name: 'Plain' }));
  expect(screen.getByText('Plain page')).toBeInTheDocument();
  expect(screen.getByRole('main')).toHaveFocus();
});

it('keeps focus on a field that the new page focused', async () => {
  const user = userEvent.setup();
  renderAt('/start');
  await user.click(screen.getByRole('button', { name: 'Form' }));
  expect(screen.getByRole('textbox', { name: 'Name' })).toHaveFocus();
});

it('leaves focus alone when only the query changes', async () => {
  const user = userEvent.setup();
  renderAt('/start');
  const next = screen.getByRole('button', { name: 'Next page' });
  await user.click(next);
  expect(next).toHaveFocus();
});

function History() {
  const navigate = useNavigate();
  return (
    <>
      <button onClick={() => navigate('/plain')}>Plain</button>
      <button onClick={() => navigate('/other', { replace: true })}>
        Replace
      </button>
      <button onClick={() => navigate(-1)}>Back</button>
    </>
  );
}

function renderHistoryAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <RouteFocus />
      <History />
      <main id="main" tabIndex={-1}>
        <Routes>
          <Route path="/" element={<Navigate to="/start" replace />} />
          <Route path="/start" element={<p>Start</p>} />
          <Route path="/plain" element={<p>Plain page</p>} />
          <Route path="/other" element={<p>Other page</p>} />
        </Routes>
      </main>
    </MemoryRouter>,
  );
}

/** The viewport's scroll position, which jsdom does not keep by itself. */
function trackScroll(initial: number) {
  let scrollTop = initial;
  vi.spyOn(document.documentElement, 'scrollTop', 'get').mockImplementation(
    () => scrollTop,
  );
  vi.spyOn(document.documentElement, 'scrollTop', 'set').mockImplementation(
    (value) => {
      scrollTop = value;
    },
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

it('leaves focus and scroll alone on a redirect of the first load', () => {
  trackScroll(120);
  renderHistoryAt('/');
  expect(screen.getByText('Start')).toBeInTheDocument();
  expect(document.body).toHaveFocus();
  expect(document.documentElement.scrollTop).toBe(120);
});

it('scrolls to the top after a navigation', async () => {
  const user = userEvent.setup();
  renderHistoryAt('/start');
  trackScroll(120);
  await user.click(screen.getByRole('button', { name: 'Plain' }));
  expect(screen.getByText('Plain page')).toBeInTheDocument();
  expect(document.documentElement.scrollTop).toBe(0);
});

it('moves focus to main and scrolls to the top on a later redirect', async () => {
  const user = userEvent.setup();
  renderHistoryAt('/');
  await user.click(screen.getByRole('button', { name: 'Plain' }));
  trackScroll(120);
  await user.click(screen.getByRole('button', { name: 'Replace' }));
  expect(screen.getByText('Other page')).toBeInTheDocument();
  expect(screen.getByRole('main')).toHaveFocus();
  expect(document.documentElement.scrollTop).toBe(0);
});

it('moves focus to main on Back but leaves the scroll position alone', async () => {
  const user = userEvent.setup();
  renderHistoryAt('/start');
  await user.click(screen.getByRole('button', { name: 'Plain' }));
  trackScroll(120);
  await user.click(screen.getByRole('button', { name: 'Back' }));
  expect(screen.getByText('Start')).toBeInTheDocument();
  expect(screen.getByRole('main')).toHaveFocus();
  expect(document.documentElement.scrollTop).toBe(120);
});
