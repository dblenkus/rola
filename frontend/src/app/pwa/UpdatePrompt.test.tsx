import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';

import { applyUpdate, dismissUpdate } from './registerServiceWorker';
import UpdatePrompt from './UpdatePrompt';

// The service worker's state, which registerServiceWorker.test.ts covers.
const worker = vi.hoisted(() => {
  const listeners = new Set<() => void>();
  const state = {
    ready: false,
    listeners,
    setReady(ready: boolean) {
      state.ready = ready;
      for (const listener of listeners) listener();
    },
  };
  return state;
});

vi.mock('./registerServiceWorker', () => ({
  isUpdateReady: () => worker.ready,
  subscribeToUpdate: (listener: () => void) => {
    worker.listeners.add(listener);
    return () => {
      worker.listeners.delete(listener);
    };
  },
  applyUpdate: vi.fn(),
  dismissUpdate: vi.fn(() => {
    worker.setReady(false);
  }),
}));

afterEach(() => {
  worker.ready = false;
  vi.clearAllMocks();
});

it('shows nothing while no new version waits', () => {
  render(<UpdatePrompt />);

  expect(screen.getByRole('status')).toBeEmptyDOMElement();
});

it('offers the new version once it waits', () => {
  render(<UpdatePrompt />);

  act(() => {
    worker.setReady(true);
  });

  expect(screen.getByRole('status')).toHaveTextContent(
    'A new version is available.',
  );
  expect(screen.getByRole('button', { name: 'Reload' })).toBeVisible();
});

it('applies the update on Reload', async () => {
  worker.ready = true;
  render(<UpdatePrompt />);

  await userEvent.click(screen.getByRole('button', { name: 'Reload' }));

  expect(applyUpdate).toHaveBeenCalledOnce();
});

it('puts the update off on Later', async () => {
  worker.ready = true;
  render(<UpdatePrompt />);

  await userEvent.click(screen.getByRole('button', { name: 'Later' }));

  expect(dismissUpdate).toHaveBeenCalledOnce();
  expect(applyUpdate).not.toHaveBeenCalled();
  expect(screen.getByRole('status')).toBeEmptyDOMElement();
});
