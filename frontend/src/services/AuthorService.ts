import { AxiosPromise } from 'axios';

import { apiClient } from './Base';
import { Author } from '../types/api';

interface UserCreatePayload {
    first_name: string;
    last_name: string;
    dob?: string;
    school?: string;
    mentor?: string;
    club?: string;
    distinction?: string;
}

export default {
    create(user: UserCreatePayload): AxiosPromise<Author> {
        /* eslint no-param-reassign: ["error", { "props": false }] */
        if (user.dob === '') delete user.dob;
        if (user.school === '') delete user.school;
        if (user.mentor === '') delete user.mentor;
        if (user.club === '') delete user.club;
        if (user.distinction === '') delete user.distinction;
        return apiClient.post('/author', user);
    },
};
