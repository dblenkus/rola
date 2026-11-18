import type { components } from '../../../shared/api/generated-api';
import { AxiosPromise } from 'axios';

import {
  PaginatedResponse,
  Submission,
  SubmissionWrite,
} from '../../../shared/api/types';

import { apiClient } from '../../../shared/api/client';

export type SubmissionCreatePayload =
  components['schemas']['SubmissionRequest'];

export default {
  // The server answers a repeated idempotency key with the submissions it
  // stored for it, so a retry after a lost response submits nothing twice.
  createSubmissions(
    submissions: SubmissionCreatePayload[],
    idempotencyKey: string,
    authorization?: string,
  ): AxiosPromise<SubmissionWrite[]> {
    return apiClient.post('/submission', submissions, {
      headers: {
        'Idempotency-Key': idempotencyKey,
        ...(authorization === undefined
          ? {}
          : { Authorization: authorization }),
      },
    });
  },
  deleteSubmission(submissionsId: number): AxiosPromise<Submission[]> {
    return apiClient.delete(`/submission/${submissionsId}`);
  },
  getSubmissionsByContest(
    contentId: number,
  ): AxiosPromise<PaginatedResponse<Submission>> {
    return apiClient.get('/submission', { params: { contest: contentId } });
  },
  getSubmissionsByTheme(
    themeId: number,
  ): AxiosPromise<PaginatedResponse<Submission>> {
    return apiClient.get('/submission', { params: { theme: themeId } });
  },
};
