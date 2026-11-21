import { AxiosPromise } from 'axios';

import { ResultsSubmission, PaginatedResponse } from '../../shared/api/types';

import { apiClient } from '../../shared/api/client';

export function getResultsSubmission(
  submissionId: string,
): AxiosPromise<ResultsSubmission> {
  return apiClient.get(`/results/submissions/${submissionId}`);
}

export function getResultsByTheme(
  themeId: string,
): AxiosPromise<PaginatedResponse<ResultsSubmission>> {
  return apiClient.get('/results/submissions', { params: { theme: themeId } });
}
