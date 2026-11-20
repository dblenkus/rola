import '@testing-library/jest-dom/vitest';
// Every test has the app's translations; jsdom's language selects English.
import '../app/i18n/config';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';
afterEach(cleanup);
