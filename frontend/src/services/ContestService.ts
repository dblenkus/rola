import { AxiosPromise } from 'axios';

import { Contest, PaginatedResponse } from '../types/api';

import { apiClient } from './Base';

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
