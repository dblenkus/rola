import type { components } from '../../../shared/api/generated-api';
import { AxiosPromise } from 'axios';

import { apiClient } from '../../../shared/api/client';
import { Author } from '../../../shared/api/types';

type UserCreatePayload = components['schemas']['AuthorRequest'];

export default {
  create(
    user: UserCreatePayload,
    authorization?: string,
  ): AxiosPromise<Author> {
    const payload = Object.fromEntries(
      Object.entries(user).filter(
        ([, value]) => value !== '' && value !== undefined,
      ),
    );
    return apiClient.post(
      '/author',
      payload,
      authorization === undefined
        ? {}
        : { headers: { Authorization: authorization } },
    );
  },
};
