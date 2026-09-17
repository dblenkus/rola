import { AxiosPromise } from 'axios';

import { ResultsTheme } from '../types/api';

import { apiClient } from './Base';

export default {
    getResults(themeId: string): AxiosPromise<ResultsTheme> {
        return apiClient.get(`/results/theme/${themeId}`);
    },
};
