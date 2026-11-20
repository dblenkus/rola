import { AxiosPromise } from 'axios';

import {
  PaginatedResponse,
  Payment,
  SubmissionSet,
} from '../../shared/api/types';

import { apiClient } from '../../shared/api/client';

export function getSubmissionSet(
  submissionSetId: string,
): AxiosPromise<SubmissionSet> {
  return apiClient.get(`/submission-sets/${submissionSetId}`);
}

export function getSubmissionSetsByContest(
  contestId: string,
  page: number,
  pageSize: number,
): AxiosPromise<PaginatedResponse<SubmissionSet>> {
  return apiClient.get('/submission-sets', {
    params: { contest: contestId, page, page_size: pageSize },
  });
}

export function deleteSubmissionSet(
  submissionsSetId: number,
): AxiosPromise<void> {
  return apiClient.delete(`/submission-sets/${submissionsSetId}`);
}

export function updatePayment(
  submissionSetId: number,
  paid: boolean,
): AxiosPromise<Payment> {
  return apiClient.put(`/payments/${submissionSetId}`, { paid });
}

export function getPaymentsBySubmissionSets(
  submissionSetIds: number[],
): AxiosPromise<PaginatedResponse<Payment>> {
  return apiClient.get('/payments', {
    params: {
      submission_set__in: submissionSetIds.join(','),
      page_size: submissionSetIds.length,
    },
  });
}
