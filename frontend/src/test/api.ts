import {
  AxiosError,
  type AxiosAdapter,
  type InternalAxiosRequestConfig,
} from 'axios';
import { onTestFinished, vi } from 'vitest';
import { apiBaseURL, apiClient } from '../shared/api/client';
import type { PaginatedResponse } from '../shared/api/types';

type Handler = (config: InternalAxiosRequestConfig, url: URL) => unknown;

class StatusResponse {
  constructor(
    readonly status: number,
    readonly data: unknown,
  ) {}
}

// A handler result answered with the given status instead of 200.
export function withStatus(status: number, data: unknown): StatusResponse {
  return new StatusResponse(status, data);
}

// Answers API requests by "METHOD /path", where the path is relative to the
// API base and excludes the query, which handlers read from `url`. Any other
// request fails.
export function serveApi(handlers: Record<string, Handler>) {
  const adapter = vi.fn<AxiosAdapter>(async (config) => {
    const url = new URL(apiClient.getUri(config), window.location.origin);
    const path = url.pathname.startsWith(`${apiBaseURL}/`)
      ? url.pathname.slice(apiBaseURL.length)
      : url.pathname;
    const request = `${config.method?.toUpperCase()} ${path}`;
    const handler = handlers[request];
    if (!handler) {
      throw new Error(`Unexpected request: ${request}`);
    }
    const result = await handler(config, url);
    if (result instanceof StatusResponse) {
      const { status, data } = result;
      return { config, data, status, statusText: '', headers: {} };
    }
    return { config, data: result, status: 200, statusText: 'OK', headers: {} };
  });
  apiClient.defaults.adapter = adapter;
  return adapter;
}

export function httpError(
  config: InternalAxiosRequestConfig,
  status: number,
  data: unknown = {},
  headers: Record<string, string> = {},
): AxiosError {
  return new AxiosError(
    `Request failed with status code ${status}`,
    AxiosError.ERR_BAD_REQUEST,
    config,
    undefined,
    { config, data, status, statusText: '', headers },
  );
}

// A request that got no response, as when the connection drops after the
// server received it.
export function networkError(config: InternalAxiosRequestConfig): AxiosError {
  return new AxiosError('Network Error', AxiosError.ERR_NETWORK, config);
}

export function page<T>(results: T[]): PaginatedResponse<T> {
  return { count: results.length, next: null, previous: null, results };
}

export function signIn(token = 'signed-in', email = 'ana@example.com'): void {
  localStorage.setItem(
    'token',
    JSON.stringify({ token, expires: '2999-01-01T00:00:00Z', email }),
  );
}

// Makes every access to site storage throw until the test ends, as browsers
// do when they block site data for the site.
export function blockStorage(): void {
  const storage = vi
    .spyOn(window, 'localStorage', 'get')
    .mockImplementation(() => {
      throw new DOMException('Access is denied', 'SecurityError');
    });
  onTestFinished(() => storage.mockRestore());
}
