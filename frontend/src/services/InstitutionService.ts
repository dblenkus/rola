import { AxiosPromise } from 'axios';

import { Institution, PaginatedResponse } from '../shared/api/types';

import { apiClient } from '../shared/api/client';

export default {
  getInstitutions(): AxiosPromise<PaginatedResponse<Institution>> {
    return apiClient.get('/institution', { params: { page_size: 1000 } });
  },
};
