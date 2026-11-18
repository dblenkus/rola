import { AxiosPromise } from 'axios';

import { Rating, PaginatedResponse } from '../shared/api/types';

import { apiClient } from '../shared/api/client';

export default {
  getForSubmission(
    submissionId: number,
  ): AxiosPromise<PaginatedResponse<Rating>> {
    return apiClient.get('/rating', { params: { submission: submissionId } });
  },
  getForTheme(themeId: number): AxiosPromise<PaginatedResponse<Rating>> {
    return apiClient.get('/rating', { params: { theme: themeId } });
  },
  updateForSubmission(
    submissionId: number,
    rating: number,
  ): AxiosPromise<Rating> {
    return apiClient.post('/rating', { submission: submissionId, rating });
  },
};
