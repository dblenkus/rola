import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

import { authorizationHeader, loadToken, rejectToken } from './token';

declare module 'axios' {
  interface AxiosRequestConfig {
    retriedWithoutToken?: boolean;
  }
}

export const apiBaseURL = '/api/v1';

const config: AxiosRequestConfig = {
  baseURL: apiBaseURL,
  headers: {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  },
};

const apiClient: AxiosInstance = axios.create(config);

let unexpectedFailureHandler: (() => void) | null = null;

// Registers what a failure no view can explain (no response, server errors)
// raises; the app registers it at start-up.
export function onUnexpectedFailure(handler: () => void): void {
  unexpectedFailureHandler = handler;
}

// A request that names its session keeps it, so that an upload acts for the
// account that started it after another account signs in.
apiClient.interceptors.request.use((config) => {
  if (!config.headers.has('Authorization')) {
    const token = loadToken();
    if (token) {
      config.headers.set('Authorization', authorizationHeader(token.token));
    }
  }
  return config;
});

// Views show client errors in place; only failures they cannot explain
// (no response, server errors) also go to the registered handler.
apiClient.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      const request = error.config;
      const sent = request?.headers.get('Authorization');
      rejectToken(sent);
      // The server rejects a revoked token even where no login is needed, so
      // a read is sent once more without it; views that need a login follow
      // the cleared session to the login page. Writes are never sent twice.
      if (sent && request?.method === 'get' && !request.retriedWithoutToken) {
        request.headers.delete('Authorization');
        request.retriedWithoutToken = true;
        return apiClient.request(request);
      }
    }
    if (
      !axios.isAxiosError(error) ||
      !error.response ||
      error.response.status >= 500
    ) {
      if (!unexpectedFailureHandler) {
        throw new Error('No handler for unexpected API failures is registered');
      }
      unexpectedFailureHandler();
    }
    return Promise.reject(error);
  },
);

export { apiClient };
