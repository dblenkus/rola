import type { components } from '../../shared/api/generated-api';
import { AxiosPromise } from 'axios';

import {
  Author,
  Image,
  Institution,
  PaginatedResponse,
  Submission,
  SubmissionSet,
} from '../../shared/api/types';

import { apiClient } from '../../shared/api/client';

type AuthorCreatePayload = components['schemas']['AuthorRequest'];
export type SubmissionSetCreatePayload =
  components['schemas']['SubmissionSetCreateRequest'];

export function createAuthor(
  user: AuthorCreatePayload,
  authorization?: string,
): AxiosPromise<Author> {
  const payload = Object.fromEntries(
    Object.entries(user).filter(
      ([, value]) => value !== '' && value !== undefined,
    ),
  );
  return apiClient.post(
    '/authors',
    payload,
    authorization === undefined
      ? {}
      : { headers: { Authorization: authorization } },
  );
}

// RFC 6266: filename* carries the full name percent-encoded, because browsers
// reject header values outside ISO-8859-1, and filename is an ASCII fallback.
function contentDisposition(name: string): string {
  const fallback = name.replace(/[^\x20-\x7E]|["\\]/g, '_');
  // encodeURIComponent throws on an unpaired UTF-16 surrogate, which a file
  // system name can hold. With the u flag a surrogate pair is one code point,
  // so \p{Surrogate} matches only unpaired surrogates.
  const wellFormed = name.replace(/\p{Surrogate}/gu, '\uFFFD');
  const encoded = encodeURIComponent(wellFormed).replace(
    /['()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
  return `attachment; filename="${fallback}"; filename*=UTF-8''${encoded}`;
}

export function uploadImage(
  image: File,
  authorization?: string,
): AxiosPromise<Image> {
  return apiClient.post('/files', image, {
    // A large photograph on a slow connection may take minutes.
    timeout: 0,
    headers: {
      'Content-Type': image.type,
      'Content-Disposition': contentDisposition(image.name),
      ...(authorization === undefined ? {} : { Authorization: authorization }),
    },
  });
}

export function getInstitutions(): AxiosPromise<
  PaginatedResponse<Institution>
> {
  return apiClient.get('/institutions', { params: { page_size: 1000 } });
}

// The server answers a repeated idempotency key with the submission set it
// stored for it, with status 200 instead of 201, so a retry after a lost
// response submits nothing twice.
export function createSubmissionSet(
  submissionSet: SubmissionSetCreatePayload,
  idempotencyKey: string,
  authorization?: string,
): AxiosPromise<SubmissionSet> {
  return apiClient.post('/submission-sets', submissionSet, {
    headers: {
      'Idempotency-Key': idempotencyKey,
      ...(authorization === undefined ? {} : { Authorization: authorization }),
    },
  });
}

export function deleteSubmission(submissionsId: number): AxiosPromise<void> {
  return apiClient.delete(`/submissions/${submissionsId}`);
}

export function getSubmissionsByContest(
  contentId: number,
): AxiosPromise<PaginatedResponse<Submission>> {
  return apiClient.get('/submissions', { params: { contest: contentId } });
}
