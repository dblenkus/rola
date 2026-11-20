import { useEffect } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import App from './App';

// The results page's code arrives only when the test releases it.
const results = vi.hoisted(() => {
  const waiting: (() => void)[] = [];
  const arrived = new Promise<void>((resolve) => waiting.push(resolve));
  return {
    arrived,
    release: () => waiting.forEach((resolve) => resolve()),
    left: { count: 0 },
  };
});

vi.mock('../features/contests/pages/ContestsList', () => ({
  default: function ContestsStub() {
    useEffect(
      () => () => {
        results.left.count += 1;
      },
      [],
    );
    return <p>Contests stub</p>;
  },
}));

vi.mock('../features/results/pages/ResultsList', async () => {
  await results.arrived;
  return { default: () => <p>Results stub</p> };
});

it('unmounts the page it leaves before the next page has loaded', async () => {
  const user = userEvent.setup();
  window.history.replaceState(null, '', '/contests');
  render(<App />);
  expect(await screen.findByText('Contests stub')).toBeInTheDocument();

  await user.click(screen.getByRole('link', { name: 'Results' }));
  expect(window.location.pathname).toBe('/results');
  expect(screen.queryByText('Contests stub')).not.toBeInTheDocument();
  expect(results.left.count).toBe(1);
  expect(screen.getByRole('progressbar')).toBeInTheDocument();

  results.release();
  expect(await screen.findByText('Results stub')).toBeInTheDocument();
});
