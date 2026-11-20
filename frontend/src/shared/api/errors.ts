import axios, { AxiosError } from 'axios';
import i18next from 'i18next';

// Messages are translated when they are produced, in the language active then.
const requestFailed = (): string => i18next.t('request_failed');
export const contentUnavailable = (): string =>
  i18next.t('content_unavailable');

export function formErrors(error: unknown): Record<string, string[]> {
  if (!axios.isAxiosError<unknown>(error)) {
    throw error;
  }
  const data = error.response?.data;
  const result: Record<string, string[]> = {};
  if (typeof data === 'object' && data !== null) {
    for (const [field, messages] of Object.entries(data)) {
      if (typeof messages === 'string') {
        result[field === 'detail' ? 'non_field_errors' : field] = [messages];
      } else if (
        Array.isArray(messages) &&
        messages.every(
          (message): message is string => typeof message === 'string',
        )
      ) {
        result[field] = messages;
      }
    }
  }
  if (!Object.keys(result).length) {
    return { non_field_errors: [requestFailed()] };
  }
  return result;
}

// Failed requests are shown where they happen. Any other error is a bug or a
// misconfiguration: it is rethrown outside the promise chain, so the browser
// console and Sentry report it as uncaught.
export function reportUnexpected(error: unknown): void {
  if (!axios.isAxiosError(error)) {
    queueMicrotask(() => {
      throw error;
    });
  }
}

// A request the client gave up on after its timeout; the API client makes
// axios report these as ETIMEDOUT rather than as a generic abort.
export function isTimeout(error: unknown): boolean {
  return axios.isAxiosError(error) && error.code === AxiosError.ETIMEDOUT;
}

// The API sends Retry-After in whole seconds. Any other value, such as an HTTP
// date from a proxy, leaves the wait unknown.
function throttledError(retryAfter: unknown): string {
  const seconds =
    typeof retryAfter === 'string' && /^\d+$/.test(retryAfter)
      ? Number(retryAfter)
      : 0;
  if (seconds < 1) {
    return i18next.t('too_many_requests');
  }
  return i18next.t('too_many_requests_retry', {
    count: Math.ceil(seconds / 60),
  });
}

// The message to show for a failed request; any other error is also reported.
export function requestError(error: unknown): string {
  reportUnexpected(error);
  if (axios.isAxiosError(error)) {
    if (isTimeout(error)) return i18next.t('request_timed_out');
    if (error.response?.status === 401) return i18next.t('session_expired');
    if (error.response?.status === 403) return i18next.t('permission_denied');
    if (error.response?.status === 404) return contentUnavailable();
    if (error.response?.status === 429)
      return throttledError(error.response.headers['retry-after']);
  }
  return requestFailed();
}
