import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

import store from '../store/index';
import { addNotificationError } from '../store/notifications/actions';
import { loadToken, rejectToken } from './token';

export const apiBaseURL = '/api/v1';

const config: AxiosRequestConfig = {
  baseURL: apiBaseURL,
  headers: {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  },
};

const apiClient: AxiosInstance = axios.create(config);

apiClient.interceptors.request.use((config) => {
  const token = loadToken();
  if (token) {
    config.headers.set('Authorization', `Token ${token.token}`);
  }
  return config;
});

// Views show client errors in place; only failures they cannot explain
// (no response, server errors) also raise a global notification.
apiClient.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      rejectToken(error.config?.headers.get('Authorization'));
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
