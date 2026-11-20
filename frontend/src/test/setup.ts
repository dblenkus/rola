import '@testing-library/jest-dom/vitest';
// Every test has the app's translations; jsdom's language selects English.
import '../app/i18n/config';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';
afterEach(cleanup);
// The document outlives each test of a file. Pages set its title and nothing
// unsets it, so a test's title assertion must not see the one before's.
afterEach(() => {
  document.title = '';
});
