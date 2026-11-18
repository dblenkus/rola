import { createSlice, isAnyOf, type PayloadAction } from '@reduxjs/toolkit';

import { Theme } from '../../../shared/api/types';
import { imageStore } from './reducerImage';
import submissionReducer, {
  submissionInit,
  submissionUpdate,
} from './reducerSubmission';
import { getEmptyTheme } from './utils';

const themeSlice = createSlice({
  name: 'upload/theme',
  initialState: getEmptyTheme,
  reducers: {
    themeInit: (state, action: PayloadAction<Theme>) => {
      const {
        id,
        is_series: isSeries = false,
        n_photos: imageNumber,
        title,
      } = action.payload;
      const submissionNumber = isSeries ? 1 : imageNumber;
      const submissionMeta = {
        imageNumber: isSeries ? imageNumber : 1,
        isSeries,
        isNew: true,
        isChanged: false,
        titleRequired: false,
        descriptionRequired: false,
      };
      return {
        ...state,
        meta: {
          ...state.meta,
          id,
          title,
        },
        submissions: Array.from({ length: submissionNumber }, (_, id) =>
          submissionReducer(
            undefined,
            submissionInit({ ...submissionMeta, id }),
          ),
        ),
      };
    },
  },
  extraReducers: (builder) => {
    builder.addMatcher(
      isAnyOf(submissionUpdate, imageStore),
      (state, action) => {
        const submissions = state.submissions.map((submission) => {
          return submission.meta.id === action.meta.submissionId
            ? submissionReducer(submission, action)
            : submission;
        });
        return { ...state, submissions };
      },
    );
  },
});

export const { themeInit } = themeSlice.actions;
export default themeSlice.reducer;
