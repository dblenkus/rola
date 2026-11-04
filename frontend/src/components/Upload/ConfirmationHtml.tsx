import { Alert } from '@mui/material';
import { useEffect, useRef, useState } from 'react';

let paypalReady: Promise<void> | undefined;
const paypalTimeout = 10_000;

function loadPaypal(): Promise<void> {
  const clientId = import.meta.env.VITE_PAYPAL_CLIENT_ID;
  if (!clientId) {
    return Promise.reject(new Error('Payment provider is not configured.'));
  }
  paypalReady ??= new Promise((resolve, reject) => {
    const script = document.createElement('script');
    const query = new URLSearchParams({
      'client-id': clientId,
      'enable-funding': 'venmo',
      currency: 'EUR',
    });
    script.src = `https://www.paypal.com/sdk/js?${query}`;
    script.dataset.sdkIntegrationSource = 'button-factory';
    script.onload = () => resolve();
    script.onerror = () => {
      paypalReady = undefined;
      script.remove();
      reject(new Error('Payment provider could not be loaded.'));
    };
    document.head.appendChild(script);
  });
  return paypalReady;
}

export default function ConfirmationHtml({ html }: { html: string }) {
  const container = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const element = container.current;
    if (!element) {
      throw new Error('Confirmation container is not mounted');
    }
    let cancelled = false;
    let settled = false;
    // Only trusted administrators edit this template, and its payment
    // scripts run after the SDK. The text, such as bank-transfer details,
    // must show even when the SDK fails or a stalled request leaves it
    // pending until the browser gives up. It is inserted once, so that a
    // late SDK does not run the template's scripts again.
    const finish = (message?: string) => {
      if (cancelled || settled) {
        return;
      }
      settled = true;
      setError(message ?? null);
      const range = document.createRange();
      range.selectNode(element);
      element.replaceChildren(range.createContextualFragment(html));
    };
    const timer = setTimeout(() => {
      finish('Payment provider could not be loaded.');
    }, paypalTimeout);
    loadPaypal()
      .then(() => {
        finish();
      })
      .catch((reason: unknown) => {
        finish(reason instanceof Error ? reason.message : String(reason));
      });
    return () => {
      cancelled = true;
      clearTimeout(timer);
      element.replaceChildren();
    };
  }, [html]);
  return (
    <>
      {error && <Alert severity="error">{error}</Alert>}
      <div ref={container} />
    </>
  );
}
