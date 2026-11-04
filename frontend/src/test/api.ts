import {
  AxiosError,
  type AxiosAdapter,
  type InternalAxiosRequestConfig,
} from 'axios';
import { vi } from 'vitest';
import { apiClient } from '../services/Base';
import type { PaginatedResponse } from '../types/api';

type Handler = (config: InternalAxiosRequestConfig) => unknown;

// Answers API requests by "METHOD /path", where the path is relative to the
// API base and excludes query parameters. Any other request fails.
export function serveApi(handlers: Record<string, Handler>) {
  const adapter = vi.fn<AxiosAdapter>(async (config) => {
    const request = `${config.method?.toUpperCase()} ${config.url}`;
    const handler = handlers[request];
    if (!handler) {
      throw new Error(`Unexpected request: ${request}`);
    }
    const data = await handler(config);
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
