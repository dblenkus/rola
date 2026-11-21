import { useSyncExternalStore } from 'react';
import {
  type Appearance,
  getAppearance,
  storeAppearance,
  subscribeAppearance,
} from './appearanceSetting';

// The appearance this page shows, and the function that changes and
// remembers it.
function useAppearance(): [Appearance, (choice: Appearance) => void] {
  const choice = useSyncExternalStore(subscribeAppearance, getAppearance);
  return [choice, storeAppearance];
}

export default useAppearance;
