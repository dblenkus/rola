import { AxiosPromise } from 'axios';

import { ResultsTheme } from '../../../shared/api/types';

import { apiClient } from '../../../shared/api/client';

export default {
  getResults(themeId: string): AxiosPromise<ResultsTheme> {
    return apiClient.get(`/results/theme/${themeId}`);
  },
};
