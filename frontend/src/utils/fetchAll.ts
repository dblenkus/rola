import { AxiosPromise } from 'axios';

import { PaginatedResponse } from '../types/api';
import { apiClient } from '../services/Base';

const fetchAll = async <T>(
  resource: () => AxiosPromise<PaginatedResponse<T>>,
): Promise<T[]> => {
  let response = await resource();
  let result = [...response.data.results];

  while (response.data.next) {
    response = await apiClient.get<PaginatedResponse<T>>(
      response.data.next.replace('http://', 'https://'),
    );
    result = [...result, ...response.data.results];
  }

  return result;
};

export default fetchAll;
