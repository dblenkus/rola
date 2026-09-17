import { AxiosPromise } from 'axios';

import { apiClient } from './Base';
import { Image } from '../types/api';

export default {
    uploadImage(image: File): AxiosPromise<Image> {
        // eslint-disable-next-line no-control-regex
        const filename = image.name.replace(/[^\u000A\u0020-\u007E]/g, ' ');
        return apiClient.post('/file', image, {
            headers: {
                'Content-Type': image.type,
                'Content-Disposition': `attachment; filename=${filename}`,
            },
        });
    },
};
