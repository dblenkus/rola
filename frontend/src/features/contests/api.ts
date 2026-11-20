import { AxiosPromise } from 'axios';

import { Contest, PaginatedResponse } from '../../shared/api/types';

import { apiClient } from '../../shared/api/client';

export function getActiveContests(): AxiosPromise<PaginatedResponse<Contest>> {
  return apiClient.get('/contests', { params: { is_active: true } });
}

export function getContest(id: string): AxiosPromise<Contest> {
  return apiClient.get(`/contests/${id}`);
}
