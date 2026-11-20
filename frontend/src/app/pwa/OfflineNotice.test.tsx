import { act, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';

import OfflineNotice from './OfflineNotice';

function goOnline(online: boolean) {
  vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(online);
  act(() => {
    window.dispatchEvent(new Event(online ? 'online' : 'offline'));
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

it('shows nothing while online', () => {
  render(<OfflineNotice />);

  expect(screen.getByRole('status')).toBeEmptyDOMElement();
});

it('follows the browser going offline and back online', () => {
  render(<OfflineNotice />);

  goOnline(false);
  expect(screen.getByRole('status')).toHaveTextContent(
    'You are offline. Photographs and results need a connection.',
  );

  goOnline(true);
  expect(screen.getByRole('status')).toBeEmptyDOMElement();
});

it('shows the notice when the page loads offline', () => {
  vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);

  render(<OfflineNotice />);

  expect(screen.getByRole('status')).toHaveTextContent('You are offline.');
});
