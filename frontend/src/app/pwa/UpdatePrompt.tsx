import { useTranslation } from 'react-i18next';

import Button from '../../shared/ui/Button';

import { applyUpdate, dismissUpdate } from './registerServiceWorker';
import { useUpdateReady } from './useUpdateReady';
import './pwa.css';

/**
 * Offers the new version once it waits. It never reloads by itself: an
 * entrant may be mid-upload or a judge mid-scoring. The live region is always
 * rendered, so screen readers announce the notice when it appears.
 */
export default function UpdatePrompt() {
  const { t } = useTranslation();
  const ready = useUpdateReady();
  return (
    <div role="status">
      {ready && (
        <div className="pwa-update">
          <p className="pwa-update__text body">{t('pwa_update_text')}</p>
          <div className="pwa-update__actions">
            <Button variant="quiet" onPress={dismissUpdate}>
              {t('pwa_update_later')}
            </Button>
            <Button variant="primary" onPress={applyUpdate}>
              {t('pwa_update_reload')}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
