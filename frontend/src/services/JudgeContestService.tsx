import { AxiosPromise } from 'axios';

import { JuryContest, PaginatedResponse } from '../shared/api/types';

import { apiClient } from '../shared/api/client';

export default {
  getContests(): AxiosPromise<PaginatedResponse<JuryContest>> {
    return apiClient.get('/judge/contest');
  },
};
