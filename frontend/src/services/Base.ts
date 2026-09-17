import axios, { AxiosInstance, AxiosRequestConfig, AxiosError } from 'axios';

import store from '../store/index';
import { addNotificationError } from '../store/notifications/actions';

const baseURL = `${process.env.REACT_APP_BASE_URL || ''}/api/v1`;

let config: AxiosRequestConfig = {
    baseURL,
    headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
    },
};

const apiClient: AxiosInstance = axios.create(config);

const authInterceptor = (config: AxiosRequestConfig): AxiosRequestConfig => {
    const tokenString = localStorage.getItem('token');
    if (tokenString) {
        const token: { token: string; expires: string } = JSON.parse(tokenString);
        if (!!token) {
            config.headers['Authorization'] = `Token ${token['token']}`;
        }
    }
    return config;
};

const notificationsInterceptor = (error: AxiosError) => {
    store.dispatch(addNotificationError('Network error occurred.'));
    return Promise.reject(error);
};

apiClient.interceptors.request.use(authInterceptor);
apiClient.interceptors.response.use((response) => response, notificationsInterceptor);

export { apiClient };
