import { describe, expect, it } from 'vitest';
import { httpError, networkError, serveApi } from '../../test/api';
import { apiClient } from './client';

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
      'GET /contest': (config) => {
        throw error(config);
      },
    });
    await expect(apiClient.get('/contest')).rejects.toThrow(
      'No handler for unexpected API failures is registered',
    );
  });

  it('passes a client error to the caller', async () => {
    serveApi({
      'GET /contest': (config) => {
        throw httpError(config, 403);
      },
    });
    await expect(apiClient.get('/contest')).rejects.toMatchObject({
      response: { status: 403 },
    });
  });
});
