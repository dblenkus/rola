import { act, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import './i18n/config';
import store from './store';
import {
  addNotificationInfo,
  deleteMessage,
} from '../features/notifications/state/actions';
import { apiClient } from '../shared/api/client';
import { signIn } from '../test/api';
import { open } from '../test/app';

// A new version waits for the whole file.
vi.mock('./pwa/useUpdateReady', () => ({ useUpdateReady: () => true }));

// Every request stays unanswered: these tests look at the shell only.
beforeEach(() => {
  localStorage.clear();
  apiClient.defaults.adapter = () => new Promise(() => {});
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
});

describe('bottom stack', () => {
  it.each([
    ['standard', '/contests', 'shell'],
    ['task', '/contest/1/upload', 'shell shell--task'],
    ['bare', '/judge/contest/1/theme/2/rate', 'shell shell--bare'],
  ])(
    'stacks the notification above the update prompt in the %s layout',
    (_layout, path, shellClass) => {
      signIn();
      open(path);
      act(() => {
        store.dispatch(addNotificationInfo('Saved for later.'));
      });

      const shell = document.querySelector('.shell');
      expect(shell?.className).toBe(shellClass);
      expect(document.querySelectorAll('.shell-bottom-stack')).toHaveLength(1);
      const stack = document.querySelector<HTMLElement>('.shell-bottom-stack');
      expect(shell).toContainElement(stack);

      const toast = screen.getByRole('alert');
      expect(toast).toHaveTextContent('Saved for later.');
      const prompt = screen
        .getByText('A new version is available.')
        .closest<HTMLElement>('[role="status"]');
      expect(prompt).toContainElement(
        screen.getByRole('button', { name: 'Reload' }),
      );
      expect(stack).toContainElement(toast);
      expect(stack).toContainElement(prompt);
      // The prompt comes last, nearest the corner.
      expect(stack?.firstElementChild).toContainElement(toast);
      expect(stack?.lastElementChild).toBe(prompt);
    },
  );
});
