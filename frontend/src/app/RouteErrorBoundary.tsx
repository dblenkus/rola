import { useEffect, useState, type ReactNode } from 'react';
import * as Sentry from '@sentry/react';
import { useTranslation } from 'react-i18next';
import { useLocation } from 'react-router';

import Button from '../shared/ui/Button';
import Page from '../shared/ui/Page';

// Shows ErrorFallback instead of a page that failed to render or whose code
// failed to load, and reports the error to Sentry. The app bar around it
// stays usable.
export default function RouteErrorBoundary({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <Sentry.ErrorBoundary
      fallback={({ resetError }) => <ErrorFallback resetError={resetError} />}
    >
      {children}
    </Sentry.ErrorBoundary>
  );
}

// Offers a reload, and shows the routed page again once the location's path
// changes, so the navigation still works after an error.
export function ErrorFallback({ resetError }: { resetError: () => void }) {
  const { t } = useTranslation();
  const { pathname } = useLocation();
  const [failedAt] = useState(pathname);
  useEffect(() => {
    if (pathname !== failedAt) {
      resetError();
    }
  }, [pathname, failedAt, resetError]);
  return (
    <Page title={t('shell_error_title')} lead={t('shell_error_text')}>
      <Button variant="primary" onPress={() => window.location.reload()}>
        {t('shell_error_reload')}
      </Button>
    </Page>
  );
}
