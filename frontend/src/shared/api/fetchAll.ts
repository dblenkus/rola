import { AxiosPromise } from 'axios';

import { PaginatedResponse } from './types';
import { apiBaseURL, apiClient } from './client';

const fetchAll = async <T>(
  resource: () => AxiosPromise<PaginatedResponse<T>>,
): Promise<T[]> => {
  // Following links outside the API would send the auth token elsewhere.
  const base = new URL(apiBaseURL, window.location.origin);
  const visited = new Set<string>();
  let response = await resource();
  const result = [...response.data.results];

  while (response.data.next) {
    const next = new URL(response.data.next, base);
    if (
      next.origin !== base.origin ||
      !next.pathname.startsWith(`${base.pathname}/`) ||
      visited.has(next.href)
    ) {
      throw new Error(`Invalid pagination URL: ${response.data.next}`);
    }
    visited.add(next.href);
    response = await apiClient.get<PaginatedResponse<T>>(next.href);
    result.push(...response.data.results);
  }

  return result;
};

export default fetchAll;
