import { screen } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import '../../../app/i18n/config';
import { serveApi, signIn } from '../../../test/api';
import { open } from '../../../test/app';
import { contest } from '../../../test/fixtures';

beforeEach(() => {
  localStorage.clear();
  signIn();
  document.documentElement.removeAttribute('data-confirmation-script');
});

it('shows the confirmation text of the contest without running its scripts', async () => {
  serveApi({
    'GET /contests/1': () => ({
      ...contest,
      // The script marks the document, which the test shares with the page,
      // with an attribute the page never sets; the page sets the title.
      // jsdom runs scripts in a window of its own, so a property set on
      // `window` would not show here even when the script ran.
      confirmation_html:
        '<p>Pay <strong>10 EUR</strong> by bank transfer.</p>' +
        '<a href="https://example.com/rules.pdf">Rules</a>' +
        '<script>document.documentElement.setAttribute(' +
        '"data-confirmation-script", "ran");</script>',
    }),
  });
  open('/contest/1/confirm');
  // Nothing below can fail before the text is on the page.
  const amount = await screen.findByText('10 EUR');
  expect(document.documentElement).not.toHaveAttribute(
    'data-confirmation-script',
  );
  expect(amount.tagName).toBe('STRONG');
  expect(screen.getByRole('link', { name: 'Rules' })).toHaveAttribute(
    'href',
    'https://example.com/rules.pdf',
  );
  expect(document.body.querySelector('script')).toBeNull();
  expect(document.head.querySelector('script[src*="paypal.com"]')).toBeNull();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('thanks the entrant and links back to the contests', async () => {
  serveApi({ 'GET /contests/1': () => contest });
  open('/contest/1/confirm');
  expect(
    await screen.findByRole('heading', {
      level: 1,
      name: 'Thank you for uploading photos!',
    }),
  ).toBeInTheDocument();
  expect(await screen.findByText('Submission received')).toBeInTheDocument();
  expect(
    screen.getByRole('link', { name: 'Back to contests' }),
  ).toHaveAttribute('href', '/contests');
});

const defaultConfirmation = 'Your photographs have been submitted.';

it.each([
  ['an empty', ''],
  ['a whitespace-only', ' \n\t '],
])(
  'shows the default confirmation text for %s contest confirmation',
  async (_, confirmationHtml) => {
    serveApi({
      'GET /contests/1': () => ({
        ...contest,
        confirmation_html: confirmationHtml,
      }),
    });
    open('/contest/1/confirm');
    expect(await screen.findByText(defaultConfirmation)).toBeInTheDocument();
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Thank you for uploading photos!',
      }),
    ).toBeInTheDocument();
  },
);

it('shows the contest confirmation text instead of the default one', async () => {
  serveApi({ 'GET /contests/1': () => contest });
  open('/contest/1/confirm');
  expect(await screen.findByText('Submission received')).toBeInTheDocument();
  expect(screen.queryByText(defaultConfirmation)).not.toBeInTheDocument();
});
