import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

import store from '../../app/store';
import { addNotificationError } from '../../features/notifications/state/actions';
import { loadToken, rejectToken } from './token';

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

// A request that names its session keeps it, so that an upload acts for the
// account that started it after another account signs in.
apiClient.interceptors.request.use((config) => {
  if (!config.headers.has('Authorization')) {
    const token = loadToken();
    if (token) {
      config.headers.set('Authorization', `Token ${token.token}`);
    }
  }
  return config;
});

// Views show client errors in place; only failures they cannot explain
// (no response, server errors) also raise a global notification.
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
      store.dispatch(addNotificationError('Network error occurred.'));
    }
    return Promise.reject(error);
  },
);

export { apiClient };
