import { isAxiosError } from 'axios';

export function formErrors(error: unknown): Record<string, string[]> {
  if (
    isAxiosError<unknown>(error) &&
    typeof error.response?.data === 'object' &&
    error.response.data !== null
  ) {
    const result: Record<string, string[]> = {};
    for (const [field, messages] of Object.entries(error.response.data)) {
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
    if (Object.keys(result).length) {
      return result;
    }
  }
  return { non_field_errors: ['Request failed. Please try again.'] };
}
