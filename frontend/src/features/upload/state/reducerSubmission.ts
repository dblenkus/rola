import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

import { InputChange, SubmissionMeta, SubmissionModel } from '../models';
import imageReducer, { imageInit, imageStore } from './reducerImage';
import { getEmptySubmission } from './utils';

// The submission an action is for; the upload and theme reducers route the
// action to that submission by it.
export interface SubmissionTarget {
  themeId: number;
  submissionId: number;
}

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

const submissionSlice = createSlice({
  name: 'upload/submission',
  initialState: getEmptySubmission,
  reducers: {
    submissionInit: (state, action: PayloadAction<SubmissionMeta>) => {
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
    },
    submissionUpdate: {
      reducer: (
        state,
        action: PayloadAction<InputChange, string, SubmissionTarget>,
      ) => {
        const { name, value } = action.payload;
        const submission = { ...state, [name]: value };
        return {
          ...submission,
          meta: {
            ...state.meta,
            ...requiredFields(submission),
            isChanged: true,
          },
        };
      },
      prepare: (
        themeId: number,
        submissionId: number,
        payload: InputChange,
      ) => ({ payload, meta: { themeId, submissionId } }),
    },
  },
  extraReducers: (builder) => {
    builder.addCase(imageStore, (state, action) => {
      const images = state.images.map((image) => {
        return image.meta.id === action.meta.imageId
          ? imageReducer(image, action)
          : image;
      });
      const submission = { ...state, images };
      return {
        ...submission,
        meta: { ...state.meta, ...requiredFields(submission) },
      };
    });
  },
});

export const { submissionInit, submissionUpdate } = submissionSlice.actions;
export default submissionSlice.reducer;
