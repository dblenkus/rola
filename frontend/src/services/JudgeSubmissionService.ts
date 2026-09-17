import { AxiosPromise } from 'axios';

import { PaginatedResponse, Submission } from '../types/api';

import { apiClient } from './Base';

export default {
    getSubmissionsByContest(contentId: number): AxiosPromise<PaginatedResponse<Submission>> {
        return apiClient.get('/judge/submission', { params: { contest: contentId } });
    },
    getSubmissionsByTheme(themeId: number): AxiosPromise<PaginatedResponse<Submission>> {
        return apiClient.get('/judge/submission', { params: { theme: themeId } });
    },
};
