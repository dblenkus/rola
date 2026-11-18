import { beforeEach, describe, expect, it } from 'vitest';
import { apiClient } from '../shared/api/client';
import store from './store';
import { deleteMessage } from '../features/notifications/state/actions';
import type { Notification } from '../features/notifications/state/reducer';
import { httpError, networkError, serveApi } from '../test/api';

beforeEach(() => {
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
});

// Every notification the store shows while the request runs.
async function notificationsDuring(request: () => Promise<unknown>) {
  const shown: Notification[] = [];
  let last = store.getState().notifications;
  const unsubscribe = store.subscribe(() => {
    const current = store.getState().notifications;
    if (current && current !== last) {
      shown.push(current);
    }
    last = current;
  });
  try {
    await request().catch(() => undefined);
  } finally {
    unsubscribe();
  }
  return shown;
}

describe('unexpected API failures', () => {
  it.each([
    [
      'a server error',
      (config: Parameters<typeof networkError>[0]) => httpError(config, 503),
    ],
    ['no response', networkError],
  ])('notify once on %s', async (_name, error) => {
    serveApi({
      'GET /contest': (config) => {
        throw error(config);
      },
    });
    const shown = await notificationsDuring(() => apiClient.get('/contest'));
    expect(shown).toEqual([
      expect.objectContaining({
        message: 'Network error occurred.',
        severity: 'error',
      }),
    ]);
  });

  it('leave a client error to the view', async () => {
    serveApi({
      'GET /contest': (config) => {
        throw httpError(config, 403, { detail: 'Forbidden' });
      },
    });
    const shown = await notificationsDuring(() => apiClient.get('/contest'));
    expect(shown).toEqual([]);
    expect(store.getState().notifications).toBeNull();
  });
});
