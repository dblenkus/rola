import { AxiosPromise } from 'axios';

import { Institution, PaginatedResponse } from '../types/api';

import { apiClient } from './Base';

export default {
    getInstitutions(): AxiosPromise<PaginatedResponse<Institution>> {
        return apiClient.get('/institution', { params: { page_size: 1000 } });
    },
};
