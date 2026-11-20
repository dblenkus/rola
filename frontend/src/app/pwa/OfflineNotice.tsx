import { useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';

import Icon from '../../shared/ui/Icon';

import './pwa.css';

function subscribe(listener: () => void): () => void {
  window.addEventListener('online', listener);
  window.addEventListener('offline', listener);
  return () => {
    window.removeEventListener('online', listener);
    window.removeEventListener('offline', listener);
  };
}

function isOnline(): boolean {
  return navigator.onLine;
}

/**
 * A band under the app bar while the browser is offline. The app shell still
 * loads from the service worker, but nothing it shows is cached. The live
 * region is always rendered, so screen readers announce the band.
 */
export default function OfflineNotice() {
  const { t } = useTranslation();
  const online = useSyncExternalStore(subscribe, isOnline);
  return (
    <div role="status">
      {!online && (
        <p className="pwa-offline small">
          <Icon name="alert" className="pwa-offline__icon" />
          {t('pwa_offline')}
        </p>
      )}
    </div>
  );
}
