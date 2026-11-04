import axios from 'axios';

const requestFailed = 'Request failed. Please try again.';

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
    return { non_field_errors: [requestFailed] };
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

// The API sends Retry-After in whole seconds. Any other value, such as an HTTP
// date from a proxy, leaves the wait unknown.
function throttledError(retryAfter: unknown): string {
  const seconds =
    typeof retryAfter === 'string' && /^\d+$/.test(retryAfter)
      ? Number(retryAfter)
      : 0;
  if (seconds < 1) {
    return 'Too many requests from this network. Please try again later.';
  }
  const minutes = Math.ceil(seconds / 60);
  const unit = minutes === 1 ? 'minute' : 'minutes';
  return `Too many requests from this network. Please try again in ${minutes} ${unit}.`;
}

// The message to show for a failed request; any other error is also reported.
export function requestError(error: unknown): string {
  reportUnexpected(error);
  if (axios.isAxiosError(error)) {
    if (error.response?.status === 401)
      return 'Your session has expired. Please log in again.';
    if (error.response?.status === 403)
      return 'You do not have permission to perform this action.';
    if (error.response?.status === 404)
      return 'The requested content is no longer available.';
    if (error.response?.status === 429)
      return throttledError(error.response.headers['retry-after']);
  }
  return requestFailed;
}
