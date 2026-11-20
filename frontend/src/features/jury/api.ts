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
  return apiClient.get('/judge/contest');
}

export function getJurySubmissionsByTheme(
  themeId: number,
): AxiosPromise<PaginatedResponse<JurySubmission>> {
  return apiClient.get('/judge/submission', { params: { theme: themeId } });
}

export function getRatingsForSubmission(
  submissionId: number,
): AxiosPromise<PaginatedResponse<Rating>> {
  return apiClient.get('/rating', { params: { submission: submissionId } });
}

export function getRatingsForTheme(
  themeId: number,
): AxiosPromise<PaginatedResponse<Rating>> {
  return apiClient.get('/rating', { params: { theme: themeId } });
}

export function deleteRating(ratingId: number): AxiosPromise<void> {
  return apiClient.delete(`/rating/${ratingId}`);
}

export function updateRatingForSubmission(
  submissionId: number,
  rating: number,
): AxiosPromise<Rating> {
  return apiClient.post('/rating', { submission: submissionId, rating });
}
