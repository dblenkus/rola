import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  httpError,
  networkError,
  serveApi,
  stallRequests,
} from '../../test/api';
import { apiClient, requestTimeout } from './client';

// This file imports no app store, so no unexpected-failure handler is
// registered.
describe('API client without an unexpected-failure handler', () => {
  it.each([
    [
      'a server error',
      (config: Parameters<typeof networkError>[0]) => httpError(config, 503),
    ],
    ['no response', networkError],
  ])('fails loudly on %s', async (_name, error) => {
    serveApi({
      'GET /contests': (config) => {
        throw error(config);
      },
    });
    await expect(apiClient.get('/contests')).rejects.toThrow(
      'No handler for unexpected API failures is registered',
    );
  });

  it('passes a client error to the caller', async () => {
    serveApi({
      'GET /contests': (config) => {
        throw httpError(config, 403);
      },
    });
    await expect(apiClient.get('/contests')).rejects.toMatchObject({
      response: { status: 403 },
    });
  });
});

describe('API client timeout', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('waits 30 seconds for a response', () => {
    expect(requestTimeout).toBe(30_000);
  });

  it('fails loudly when a stalled request times out', async () => {
    stallRequests();
    let failure: unknown = null;
    const request = apiClient.get('/contests').catch((error: unknown) => {
      failure = error;
    });
    await vi.advanceTimersByTimeAsync(requestTimeout - 1);
    expect(failure).toBeNull();
    await vi.advanceTimersByTimeAsync(1);
    await request;
    expect(failure).toEqual(
      new Error('No handler for unexpected API failures is registered'),
    );
  });
});
