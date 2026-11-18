import { AxiosPromise } from 'axios';

import {
  ResultsSubmission,
  ResultsTheme,
  PaginatedResponse,
} from '../../shared/api/types';

import { apiClient } from '../../shared/api/client';

export function getResultsSubmission(
  submissionId: string,
): AxiosPromise<ResultsSubmission> {
  return apiClient.get(`/results/submission/${submissionId}`);
}

export function getResultsOverview(
  themeId: string,
): AxiosPromise<PaginatedResponse<ResultsSubmission>> {
  return apiClient.get('/results/submission', {
    params: { ordering: '-rating_sum', page_size: 500, theme: themeId },
  });
}

export function getThemeResults(themeId: string): AxiosPromise<ResultsTheme> {
  return apiClient.get(`/results/theme/${themeId}`);
}
