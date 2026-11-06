import { AxiosPromise } from 'axios';

import { JurySubmission, PaginatedResponse } from '../types/api';

import { apiClient } from './Base';

export default {
  getSubmissionsByContest(
    contentId: number,
  ): AxiosPromise<PaginatedResponse<JurySubmission>> {
    return apiClient.get('/judge/submission', {
      params: { contest: contentId },
    });
  },
  getSubmissionsByTheme(
    themeId: number,
  ): AxiosPromise<PaginatedResponse<JurySubmission>> {
    return apiClient.get('/judge/submission', { params: { theme: themeId } });
  },
};
