import { AxiosPromise } from 'axios';

import { Payment, PaginatedResponse } from '../types/api';

import { apiClient } from './Base';

export default {
    updatePayment(submissionSetId: number, paid: boolean): AxiosPromise<Payment> {
        return apiClient.post('/payment', { submissionset: submissionSetId, paid });
    },
    getBySubmissionSets(submissionSetIds: number[]): AxiosPromise<PaginatedResponse<Payment>> {
        return apiClient.get('/payment', {
            params: {
                // eslint-disable-next-line @typescript-eslint/camelcase
                submissionset__in: submissionSetIds.join(','),
                // eslint-disable-next-line @typescript-eslint/camelcase
                page_size: submissionSetIds.length,
            },
        });
    },
};
