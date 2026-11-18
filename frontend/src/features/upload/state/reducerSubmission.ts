import { SubmissionModel } from '../models';

import { imageInit } from './actions';
import { SUBMISSION_INIT, SUBMISSION_UPDATE, UploadActionTypes } from './types';
import imageReducer from './reducerImage';
import { getEmptySubmission } from './utils';

interface RequiredFields {
  titleRequired: boolean;
  descriptionRequired: boolean;
}

// A selected photograph needs a title, and a series needs both texts once it
// has a photograph or either text. Derived from the whole submission so that
// clearing one field cannot lift a requirement the rest of it sets.
const requiredFields = ({
  meta,
  title,
  description,
  images,
}: SubmissionModel): RequiredFields => {
  const anyImage = images.some((image) => !!image.file);
  return {
    titleRequired: anyImage || (meta.isSeries && !!description),
    descriptionRequired: meta.isSeries && (anyImage || !!title),
  };
};

const initialSate = getEmptySubmission();

const reducer = (
  state = initialSate,
  action: UploadActionTypes,
): SubmissionModel => {
  switch (action.type) {
    case SUBMISSION_INIT: {
      const { imageNumber } = action.payload;
      const imageMeta = {
        isNew: true,
        isChanged: false,
      };
      return {
        ...state,
        meta: action.payload,
        images: Array.from({ length: imageNumber }, (_, image_id) =>
          imageReducer(undefined, imageInit({ ...imageMeta, id: image_id })),
        ),
      };
    }
    case SUBMISSION_UPDATE: {
      const { name, value } = action.payload;
      const submission = { ...state, [name]: value };
      return {
        ...submission,
        meta: { ...state.meta, ...requiredFields(submission), isChanged: true },
      };
    }
    default: {
      if ('image_id' in action) {
        const images = state.images.map((image) => {
          return image.meta.id === action.image_id
            ? imageReducer(image, action)
            : image;
        });
        const submission = { ...state, images };
        return {
          ...submission,
          meta: { ...state.meta, ...requiredFields(submission) },
        };
      }
      return state;
    }
  }
};

export default reducer;
