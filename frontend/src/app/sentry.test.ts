import * as Sentry from '@sentry/react';
import { AxiosError, AxiosHeaders } from 'axios';
import { afterAll, afterEach, beforeAll, expect, it, vi } from 'vitest';

const dsn = 'https://public@sentry.example.invalid/1';

// The options read the build environment when the module loads.
async function importSentryOptions(): Promise<Sentry.BrowserOptions> {
  vi.resetModules();
  const { sentryOptions } = await import('./sentry');
  return sentryOptions;
}

function recordPayloads(
  payloads: string[],
): NonNullable<Sentry.BrowserOptions['transport']> {
  return (options) =>
    Sentry.createTransport(options, async ({ body }) => {
      payloads.push(
        typeof body === 'string' ? body : new TextDecoder().decode(body),
      );
      return { statusCode: 200 };
    });
}

// Sentry wraps fetch once, at the first init, so the stub must come first.
beforeAll(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(null, { status: 500 })),
  );
});

afterEach(async () => {
  await Sentry.close();
  vi.unstubAllEnvs();
  window.history.replaceState(null, '', '/');
});

afterAll(() => {
  vi.unstubAllGlobals();
});

it('reports to the DSN from the build environment', async () => {
  vi.stubEnv('VITE_SENTRY_DSN', dsn);
  expect((await importSentryOptions()).dsn).toBe(dsn);
});

it('sends nothing without a DSN', async () => {
  vi.stubEnv('VITE_SENTRY_DSN', '');
  const payloads: string[] = [];
  Sentry.init({
    ...(await importSentryOptions()),
    transport: recordPayloads(payloads),
  });

  Sentry.captureException(new Error('Request failed'));
  await Sentry.flush(2000);

  expect(payloads).toEqual([]);
});

it('sends error events without credentials or URL tokens', async () => {
  vi.stubEnv('VITE_SENTRY_DSN', dsn);
  const payloads: string[] = [];
  Sentry.init({
    ...(await importSentryOptions()),
    transport: recordPayloads(payloads),
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
    headers: new AxiosHeaders({ Authorization: 'Bearer credential-secret' }),
  });

  await fetch(`${window.location.origin}/api/v1/contests`, {
    headers: { Authorization: 'Bearer credential-secret' },
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
