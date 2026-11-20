import { createRoot } from 'react-dom/client';
import * as Sentry from '@sentry/react';
import '@fontsource/roboto/300.css';
import '@fontsource/roboto/400.css';
import '@fontsource/roboto/500.css';
import '@fontsource/roboto/700.css';
import '../design/fonts.css';
import '../design/tokens.css';
import '../design/components.css';
import '../design/app.css';
import './i18n/config';
import App from './App';
import { sentryOptions } from './sentry';

Sentry.init(sentryOptions);
const root = document.getElementById('root');
if (!root) {
  throw new Error('Application root is missing');
}
createRoot(root).render(<App />);
