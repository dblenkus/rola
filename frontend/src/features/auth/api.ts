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
  return apiClient.post('/tokens', payload);
}

// Names the session to expire, because logging out removes it from storage
// before the request is sent.
export function logoutUser(authorization: string): AxiosPromise<void> {
  return apiClient.delete('/tokens/current', {
    headers: { Authorization: authorization },
  });
}

export function registerUser(payload: RegisterPayload): AxiosPromise<void> {
  return apiClient.post('/users', payload);
}

export function activateUser(payload: ActivateUserPayload): AxiosPromise<void> {
  return apiClient.post('/activations', payload);
}

export function requestPasswordReset(
  payload: RequestPasswordResetPayload,
): AxiosPromise<void> {
  return apiClient.post('/password-reset-requests', payload);
}

export function resetPassword(
  payload: PasswordResetPayload,
): AxiosPromise<void> {
  return apiClient.post('/password-resets', payload);
}
