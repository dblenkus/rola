import { AxiosPromise } from 'axios';

import { apiClient } from './Base';

export interface LoginPayload {
    email: string;
    password: string;
}

export interface RegisterPayload {
    first_name: string;
    last_name: string;
    email: string;
    password: string;
    address: string;
    city: string;
    postal_code: string;
    country: string;
}

export interface ActivateUserPayload {
    token: string;
}

export interface RequestPasswordResetPayload {
    email: string;
}

export interface PasswordResetPayload {
    new_password: string;
    token: string;
}

export default {
    login(payload: LoginPayload): AxiosPromise {
        return apiClient.post('/user/login', payload);
    },
    register(payload: RegisterPayload): AxiosPromise {
        return apiClient.post('/user', payload);
    },
    activateUser(payload: ActivateUserPayload): AxiosPromise {
        return apiClient.post('/user/activate_account', payload);
    },
    requestPasswordReset(payload: RequestPasswordResetPayload): AxiosPromise {
        return apiClient.post('/user/request_password_reset', payload);
    },
    passwordReset(payload: PasswordResetPayload): AxiosPromise {
        return apiClient.post('/user/password_reset', payload);
    },
};
