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
  return apiClient.get(`/submissionset/${submissionSetId}`);
}

export function getSubmissionSetsByContest(
  contestId: string,
  page: number,
  pageSize: number,
): AxiosPromise<PaginatedResponse<SubmissionSet>> {
  return apiClient.get('/submissionset', {
    params: { contest: contestId, page, page_size: pageSize },
  });
}

export function deleteSubmissionSet(
  submissionsSetId: number,
): AxiosPromise<void> {
  return apiClient.delete(`/submissionset/${submissionsSetId}`);
}

export function updatePayment(
  submissionSetId: number,
  paid: boolean,
): AxiosPromise<Payment> {
  return apiClient.post('/payment', { submission_set: submissionSetId, paid });
}

export function getPaymentsBySubmissionSets(
  submissionSetIds: number[],
): AxiosPromise<PaginatedResponse<Payment>> {
  return apiClient.get('/payment', {
    params: {
      submission_set__in: submissionSetIds.join(','),
      page_size: submissionSetIds.length,
    },
  });
}
