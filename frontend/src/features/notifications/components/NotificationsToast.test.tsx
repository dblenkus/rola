import { act, fireEvent, render, screen } from '@testing-library/react';
import { Provider } from 'react-redux';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { createAppStore, type AppStore } from '../../../app/store';
import {
  addNotificationError,
  addNotificationInfo,
  addNotificationSuccess,
  addNotificationWarning,
} from '../state/actions';
import Notifications from './Notifications';

let store: AppStore;

beforeEach(() => {
  vi.useFakeTimers();
  store = createAppStore();
  render(
    <Provider store={store}>
      <button type="button">Elsewhere</button>
      <Notifications />
    </Provider>,
  );
});

afterEach(() => {
  vi.useRealTimers();
});

function notify(action: ReturnType<typeof addNotificationError>): void {
  act(() => {
    store.dispatch(action);
  });
}

function wait(ms: number): void {
  act(() => {
    vi.advanceTimersByTime(ms);
  });
}

it('hides a notification after five seconds', () => {
  notify(addNotificationInfo('Saved for later.'));
  wait(4999);
  expect(screen.getByRole('alert')).toHaveTextContent('Saved for later.');
  wait(1);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(store.getState().notifications).toBeNull();
});

it('closes with its close button', () => {
  notify(addNotificationInfo('Saved for later.'));
  fireEvent.click(screen.getByRole('button', { name: 'Close' }));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(store.getState().notifications).toBeNull();
});

it('closes with Escape while focus is inside it', () => {
  notify(addNotificationInfo('Saved for later.'));
  const close = screen.getByRole('button', { name: 'Close' });
  act(() => close.focus());
  fireEvent.keyDown(close, { key: 'Escape' });
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('waits while the pointer is over it', () => {
  notify(addNotificationInfo('Saved for later.'));
  const alert = screen.getByRole('alert');
  wait(4000);
  fireEvent.pointerEnter(alert);
  wait(30000);
  expect(screen.getByRole('alert')).toBeInTheDocument();

  fireEvent.pointerLeave(alert);
  wait(4999);
  expect(screen.getByRole('alert')).toBeInTheDocument();
  wait(1);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('waits while focus is inside it', () => {
  notify(addNotificationInfo('Saved for later.'));
  act(() => screen.getByRole('button', { name: 'Close' }).focus());
  wait(30000);
  expect(screen.getByRole('alert')).toBeInTheDocument();

  act(() => screen.getByRole('button', { name: 'Elsewhere' }).focus());
  wait(4999);
  expect(screen.getByRole('alert')).toBeInTheDocument();
  wait(1);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('does not take focus when it appears', () => {
  const elsewhere = screen.getByRole('button', { name: 'Elsewhere' });
  act(() => elsewhere.focus());
  notify(addNotificationError('Request failed.'));
  expect(elsewhere).toHaveFocus();
});

it('marks errors with the alert icon and success with the check', () => {
  notify(addNotificationError('Request failed.'));
  const error = screen.getByRole('alert');
  expect(error).toHaveClass('ui-message--error');
  expect(error.querySelector('svg path')).toHaveAttribute(
    'd',
    'M8 4.5V9M8 11v.5',
  );

  notify(addNotificationSuccess('Saved.'));
  const success = screen.getByRole('alert');
  expect(success).not.toHaveClass('ui-message--error');
  expect(success.querySelector('svg path')).toHaveAttribute(
    'd',
    'M3 8.5l3.25 3.25L13 5',
  );

  notify(addNotificationWarning('Check the dates.'));
  expect(screen.getByRole('alert').querySelector('svg path')).toHaveAttribute(
    'd',
    'M8 4.5V9M8 11v.5',
  );

  notify(addNotificationInfo('Saved for later.'));
  const info = screen.getByRole('alert');
  // Only the close button's cross: info has no icon of its own.
  expect(info.querySelectorAll('svg')).toHaveLength(1);
  expect(document.querySelector('[class*="Mui"]')).toBeNull();
});
