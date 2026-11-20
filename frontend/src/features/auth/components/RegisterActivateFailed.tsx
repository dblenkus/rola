import { useTranslation } from 'react-i18next';
import Confirm from './utils/Confirm';

export default function RegisterActivateFailed() {
  const { t } = useTranslation();

  return <Confirm title={t('activation_failed')}>{t('invalid_token')}</Confirm>;
}
