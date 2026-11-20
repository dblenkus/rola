import { useSyncExternalStore } from 'react';

import { isUpdateReady, subscribeToUpdate } from './registerServiceWorker';

/** Whether to offer a waiting new version; re-renders when that changes. */
export function useUpdateReady(): boolean {
  return useSyncExternalStore(subscribeToUpdate, isUpdateReady);
}
