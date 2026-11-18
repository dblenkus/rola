import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
// Each test imports the component afresh for its own SDK promise. Loading MUI
// here keeps its first, slow import out of every test's time limit.
import '@mui/material';

const template = '<p>Pay 10 EUR by bank transfer.</p>';

function sdkScript(): HTMLScriptElement {
  const script = document.querySelector<HTMLScriptElement>(
    'script[src^="https://www.paypal.com/sdk/js"]',
  );
  if (!script) {
    throw new Error('The PayPal SDK script was not requested');
  }
  return script;
}

// The SDK promise is cached per module, so every test gets a fresh module.
async function importConfirmationHtml() {
  const { default: ConfirmationHtml } = await import('./ConfirmationHtml');
  return ConfirmationHtml;
}

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  document
    .querySelectorAll('script[src^="https://www.paypal.com/sdk/js"]')
    .forEach((script) => script.remove());
});

it('inserts the template after the payment SDK loads', async () => {
  vi.stubEnv('VITE_PAYPAL_CLIENT_ID', 'test-client');
  const ConfirmationHtml = await importConfirmationHtml();
  render(<ConfirmationHtml html={template} />);
  const script = sdkScript();
  expect(new URL(script.src).searchParams.get('client-id')).toBe('test-client');
  expect(screen.queryByText('Pay 10 EUR by bank transfer.')).toBeNull();
  fireEvent.load(script);
  expect(
    await screen.findByText('Pay 10 EUR by bank transfer.'),
  ).toBeInTheDocument();
  expect(screen.queryByRole('alert')).toBeNull();
});

it('shows the template and an error when the payment SDK fails to load', async () => {
  vi.stubEnv('VITE_PAYPAL_CLIENT_ID', 'test-client');
  const ConfirmationHtml = await importConfirmationHtml();
  render(<ConfirmationHtml html={template} />);
  fireEvent.error(sdkScript());
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Payment provider could not be loaded.',
  );
  expect(screen.getByText('Pay 10 EUR by bank transfer.')).toBeInTheDocument();
});

it('shows the template and an error when the payment SDK does not answer', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  vi.stubEnv('VITE_PAYPAL_CLIENT_ID', 'test-client');
  const ConfirmationHtml = await importConfirmationHtml();
  render(<ConfirmationHtml html={template} />);
  const script = sdkScript();
  act(() => {
    vi.advanceTimersByTime(9_999);
  });
  expect(screen.queryByText('Pay 10 EUR by bank transfer.')).toBeNull();
  act(() => {
    vi.advanceTimersByTime(1);
  });
  expect(screen.getByRole('alert')).toHaveTextContent(
    'Payment provider could not be loaded.',
  );
  const text = screen.getByText('Pay 10 EUR by bank transfer.');
  await act(async () => {
    fireEvent.load(script);
  });
  expect(screen.getByText('Pay 10 EUR by bank transfer.')).toBe(text);
});

it('retries the payment SDK after an earlier load failed', async () => {
  vi.stubEnv('VITE_PAYPAL_CLIENT_ID', 'test-client');
  const ConfirmationHtml = await importConfirmationHtml();
  const first = render(<ConfirmationHtml html="<p>First confirmation</p>" />);
  const failed = sdkScript();
  fireEvent.error(failed);
  expect(await screen.findByText('First confirmation')).toBeInTheDocument();
  first.unmount();
  render(<ConfirmationHtml html="<p>Second confirmation</p>" />);
  const retry = sdkScript();
  expect(retry).not.toBe(failed);
  fireEvent.load(retry);
  expect(await screen.findByText('Second confirmation')).toBeInTheDocument();
  expect(screen.queryByRole('alert')).toBeNull();
});

it('shows the template and an error when no PayPal client is configured', async () => {
  vi.stubEnv('VITE_PAYPAL_CLIENT_ID', '');
  const ConfirmationHtml = await importConfirmationHtml();
  render(<ConfirmationHtml html={template} />);
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Payment provider is not configured.',
  );
  expect(screen.getByText('Pay 10 EUR by bank transfer.')).toBeInTheDocument();
  expect(
    document.querySelector('script[src^="https://www.paypal.com/sdk/js"]'),
  ).toBeNull();
});
