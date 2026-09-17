import { AxiosPromise } from 'axios';

import { PaginatedResponse, SubmissionSet } from '../types/api';

import { apiClient } from './Base';

export default {
    getSubmissionSet(submissionSetId: string): AxiosPromise<SubmissionSet> {
        return apiClient.get(`/submissionset/${submissionSetId}`);
    },
    getByContest(
        contestId: string,
        page: number,
        pageSize: number,
    ): AxiosPromise<PaginatedResponse<SubmissionSet>> {
        return apiClient.get('/submissionset', {
            params: { contest: contestId, page, page_size: pageSize },
        });
    },
    deleteSubmissionSet(submissionsSetId: number): AxiosPromise<void> {
        return apiClient.delete(`/submissionset/${submissionsSetId}`);
    },
};
