import { createRoot } from 'react-dom/client';
import * as Sentry from '@sentry/react';
// The layers first (src/design/layers.css), which bring tokens.css and
// components.css.
import '../design/layers.css';
import '../design/fonts.css';
import '../design/app.css';
import './i18n/config';
import App from './App';
import { registerServiceWorker } from './pwa/registerServiceWorker';
import { sentryOptions } from './sentry';

Sentry.init(sentryOptions);
// Only the production build has a worker; the development server has none.
if (import.meta.env.PROD) {
  registerServiceWorker();
}
const root = document.getElementById('root');
if (!root) {
  throw new Error('Application root is missing');
}
// Errors that no boundary catches, those that one does, and those React
// recovers from all go to Sentry, which reports each error once.
const report = Sentry.reactErrorHandler();
// React's error info may leave componentStack out, where Sentry's type wants
// it present or null. The console keeps the error too, as React logs it
// without these options.
const reportError = (
  error: unknown,
  { componentStack }: { componentStack?: string | undefined },
) => {
  report(error, { componentStack: componentStack ?? null });
  console.error(error);
};
createRoot(root, {
  onUncaughtError: reportError,
  onCaughtError: reportError,
  onRecoverableError: reportError,
}).render(<App />);
