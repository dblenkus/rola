import type { components } from '../../shared/api/generated-api';
import { AxiosPromise } from 'axios';

import { apiClient } from '../../shared/api/client';
import type { AuthToken } from '../../shared/api/token';

type Schemas = components['schemas'];
export type LoginPayload = Schemas['LoginRequest'];
export type RegisterPayload = Schemas['UserRequest'];
export type ActivateUserPayload = Schemas['ActivationRequest'];
export type RequestPasswordResetPayload =
  Schemas['RequestPasswordResetRequest'];
export type PasswordResetPayload = Schemas['PasswordResetRequest'];

export function loginUser(payload: LoginPayload): AxiosPromise<AuthToken> {
  return apiClient.post('/user/login', payload);
}

// Names the session to expire, because logging out removes it from storage
// before the request is sent.
export function logoutUser(authorization: string): AxiosPromise<void> {
  return apiClient.post('/user/logout', undefined, {
    headers: { Authorization: authorization },
  });
}

export function registerUser(payload: RegisterPayload): AxiosPromise {
  return apiClient.post('/user', payload);
}

export function activateUser(payload: ActivateUserPayload): AxiosPromise {
  return apiClient.post('/user/activate_account', payload);
}

export function requestPasswordReset(
  payload: RequestPasswordResetPayload,
): AxiosPromise {
  return apiClient.post('/user/request_password_reset', payload);
}

export function resetPassword(payload: PasswordResetPayload): AxiosPromise {
  return apiClient.post('/user/password_reset', payload);
}
