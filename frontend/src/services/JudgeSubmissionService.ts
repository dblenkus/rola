import { AxiosPromise } from 'axios';

import { JurySubmission, PaginatedResponse } from '../shared/api/types';

import { apiClient } from '../shared/api/client';

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
