import { AxiosPromise } from 'axios';

import {
  JuryContest,
  JurySubmission,
  PaginatedResponse,
  Rating,
} from '../../shared/api/types';

import { apiClient } from '../../shared/api/client';

export function getJuryContests(): AxiosPromise<
  PaginatedResponse<JuryContest>
> {
  return apiClient.get('/judging/contests');
}

export function getJurySubmissionsByTheme(
  themeId: number,
): AxiosPromise<PaginatedResponse<JurySubmission>> {
  return apiClient.get('/judging/submissions', { params: { theme: themeId } });
}

export function getRatingsForSubmission(
  submissionId: number,
): AxiosPromise<PaginatedResponse<Rating>> {
  return apiClient.get('/judging/ratings', {
    params: { submission: submissionId },
  });
}

export function getRatingsForTheme(
  themeId: number,
): AxiosPromise<PaginatedResponse<Rating>> {
  return apiClient.get('/judging/ratings', { params: { theme: themeId } });
}

export function deleteRating(submissionId: number): AxiosPromise<void> {
  return apiClient.delete(`/judging/ratings/${submissionId}`);
}

export function updateRatingForSubmission(
  submissionId: number,
  rating: number,
): AxiosPromise<Rating> {
  return apiClient.put(`/judging/ratings/${submissionId}`, { rating });
}
