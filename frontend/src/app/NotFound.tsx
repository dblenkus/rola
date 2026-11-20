import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

import Page from '../shared/ui/Page';

// Every location that no route matches.
export default function NotFound() {
  const { t } = useTranslation();
  return (
    <Page title={t('shell_not_found_title')} lead={t('shell_not_found_text')}>
      <p className="body">
        <Link to="/">{t('shell_not_found_home')}</Link>
      </p>
    </Page>
  );
}
