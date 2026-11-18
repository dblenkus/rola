import { act, render, screen } from '@testing-library/react';
import { Provider } from 'react-redux';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import store from '../../../app/store';
import { addNotificationError } from '../state/actions';
import Notifications from './Notifications';

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

it('clears a burst of errors five seconds after the last one', () => {
  render(
    <Provider store={store}>
      <Notifications />
    </Provider>,
  );

  for (const message of ['First error.', 'Second error.', 'Third error.']) {
    act(() => {
      store.dispatch(addNotificationError(message));
    });
    act(() => {
      vi.advanceTimersByTime(500);
    });
  }
  expect(screen.getByRole('alert')).toHaveTextContent('Third error.');

  act(() => {
    vi.advanceTimersByTime(4400);
  });
  expect(screen.getByRole('alert')).toHaveTextContent('Third error.');

  act(() => {
    vi.advanceTimersByTime(100);
  });
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();

  act(() => {
    vi.advanceTimersByTime(30000);
  });
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
