import { ImageModel } from '../../types/models';

import { IMAGE_INIT, IMAGE_STORE, UploadActionTypes } from './types';
import { getEmptyImage } from './utils';

const initialSate = getEmptyImage();

const reducer = (state = initialSate, action: UploadActionTypes): ImageModel => {
    switch (action.type) {
        case IMAGE_INIT:
            return {
                ...state,
                meta: action.payload,
            };
        case IMAGE_STORE:
            return {
                ...state,
                meta: { ...state.meta, isChanged: true },
                ...action.payload,
            };
        default:
            return state;
    }
};

export default reducer;
