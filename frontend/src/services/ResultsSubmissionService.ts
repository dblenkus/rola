import { AxiosPromise } from 'axios';

import { ResultsSubmission, PaginatedResponse } from '../types/api';

import { apiClient } from './Base';

export default {
    get(submissionId: string): AxiosPromise<ResultsSubmission> {
        return apiClient.get(`/results/submission/${submissionId}`);
    },
    getOverview(themeId: string): AxiosPromise<PaginatedResponse<ResultsSubmission>> {
        return apiClient.get('/results/submission', {
            params: { ordering: '-rating_sum', page_size: 500, theme: themeId },
        });
    },
};
