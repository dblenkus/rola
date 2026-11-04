import * as Sentry from '@sentry/react';
import { AxiosError, AxiosHeaders } from 'axios';
import { afterEach, expect, it, vi } from 'vitest';
import { sentryOptions } from './sentry';

afterEach(async () => {
  await Sentry.close();
  vi.unstubAllGlobals();
  window.history.replaceState(null, '', '/');
});

it('sends error events without credentials or URL tokens', async () => {
  const payloads: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(null, { status: 500 })),
  );
  Sentry.init({
    ...sentryOptions,
    transport: (options) =>
      Sentry.createTransport(options, async ({ body }) => {
        payloads.push(
          typeof body === 'string' ? body : new TextDecoder().decode(body),
        );
        return { statusCode: 200 };
      }),
  });
  // The default integrations send no request headers; failed-request events
  // from this integration do.
  Sentry.addIntegration(Sentry.httpClientIntegration());
  Object.defineProperty(document, 'referrer', {
    configurable: true,
    value: `${window.location.origin}/register/activate?token=activation-secret`,
  });
  window.history.pushState(null, '', '/judge/contest/1?token=history-secret');
  window.history.pushState(null, '', '/password-reset?token=reset-secret');
  const error = new AxiosError('Request failed', 'ERR_BAD_RESPONSE', {
    headers: new AxiosHeaders({ Authorization: 'Token credential-secret' }),
  });

  await fetch(`${window.location.origin}/api/v1/contest`, {
    headers: { Authorization: 'Token credential-secret' },
  });
  Sentry.captureException(error);
  await Sentry.flush(2000);

  const payload = payloads.join('\n');
  expect(payload).toContain('HTTP Client Error with status code: 500');
  expect(payload).toContain('Request failed');
  expect(payload).toContain('/password-reset');
  expect(payload).toContain('"infer_ip":"never"');
  expect(payload.toLowerCase()).not.toContain('authorization');
  expect(payload).not.toContain('token=');
  expect(payload).not.toMatch(/secret/);
});
