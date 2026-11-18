import { AxiosPromise } from 'axios';

import { Payment, PaginatedResponse } from '../shared/api/types';

import { apiClient } from '../shared/api/client';

export default {
  updatePayment(submissionSetId: number, paid: boolean): AxiosPromise<Payment> {
    return apiClient.post('/payment', { submissionset: submissionSetId, paid });
  },
  getBySubmissionSets(
    submissionSetIds: number[],
  ): AxiosPromise<PaginatedResponse<Payment>> {
    return apiClient.get('/payment', {
      params: {
        submissionset__in: submissionSetIds.join(','),
        page_size: submissionSetIds.length,
      },
    });
  },
};
