import {
  AxiosError,
  type AxiosAdapter,
  type InternalAxiosRequestConfig,
} from 'axios';
import { vi } from 'vitest';
import { apiBaseURL, apiClient } from '../services/Base';
import type { PaginatedResponse } from '../types/api';

type Handler = (config: InternalAxiosRequestConfig, url: URL) => unknown;

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
    const data = await handler(config, url);
    return { config, data, status: 200, statusText: 'OK', headers: {} };
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

export function page<T>(results: T[]): PaginatedResponse<T> {
  return { count: results.length, next: null, previous: null, results };
}

export function signIn(token = 'signed-in'): void {
  localStorage.setItem(
    'token',
    JSON.stringify({ token, expires: '2999-01-01T00:00:00Z' }),
  );
}
