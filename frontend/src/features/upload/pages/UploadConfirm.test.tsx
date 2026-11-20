import { screen } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import '../../../app/i18n/config';
import { serveApi, signIn } from '../../../test/api';
import { open } from '../../../test/app';
import { contest } from '../../../test/fixtures';

beforeEach(() => {
  localStorage.clear();
  signIn();
  document.title = 'Rola';
});

it('shows the confirmation text of the contest without running its scripts', async () => {
  serveApi({
    'GET /contest/1': () => ({
      ...contest,
      // The script changes the document, which the test shares with the page.
      // jsdom runs scripts in a window of its own, so a property set on
      // `window` would not show here even when the script ran.
      confirmation_html:
        '<p>Pay <strong>10 EUR</strong> by bank transfer.</p>' +
        '<a href="https://example.com/rules.pdf">Rules</a>' +
        '<script>document.title = "Confirmation script ran";</script>',
    }),
  });
  open('/contest/1/confirm');
  // Nothing below can fail before the text is on the page.
  const amount = await screen.findByText('10 EUR');
  expect(document.title).toBe('Rola');
  expect(amount.tagName).toBe('STRONG');
  expect(screen.getByRole('link', { name: 'Rules' })).toHaveAttribute(
    'href',
    'https://example.com/rules.pdf',
  );
  expect(document.body.querySelector('script')).toBeNull();
  expect(document.head.querySelector('script[src*="paypal.com"]')).toBeNull();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
