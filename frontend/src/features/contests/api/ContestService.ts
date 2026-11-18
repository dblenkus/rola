import { AxiosPromise } from 'axios';

import { Contest, PaginatedResponse } from '../../../shared/api/types';

import { apiClient } from '../../../shared/api/client';

export default {
  getContests(): AxiosPromise<PaginatedResponse<Contest>> {
    return apiClient.get('/contest');
  },
  getActiveContests(): AxiosPromise<PaginatedResponse<Contest>> {
    return apiClient.get('/contest', { params: { is_active: true } });
  },
  getContest(id: string): AxiosPromise<Contest> {
    return apiClient.get(`/contest/${id}`);
  },
};
