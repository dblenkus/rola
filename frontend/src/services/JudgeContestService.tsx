import { AxiosPromise } from 'axios';

import { JuryContest, PaginatedResponse } from '../types/api';

import { apiClient } from './Base';

export default {
    getContests(): AxiosPromise<PaginatedResponse<JuryContest>> {
        return apiClient.get('/judge/contest');
    },
};
