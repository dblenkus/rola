import { act, render } from '@testing-library/react';
import { beforeAll } from 'vitest';
import App from '../app/App';
import { preloadPages } from '../app/routes';

// The pages load lazily. Importing them once up front keeps a cold dynamic
// import from outlasting the tests' findBy timeouts.
beforeAll(async () => {
  await preloadPages();
});

// Renders the whole app at the given location.
export function open(path: string): void {
  window.history.replaceState(null, '', path);
  render(<App />);
}

// Moves the rendered app to another location, as the browser's back and
// forward buttons do, so the current view stays mounted.
export function travel(path: string): void {
  act(() => {
    window.history.pushState(null, '', path);
    window.dispatchEvent(new PopStateEvent('popstate'));
  });
}
