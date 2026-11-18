import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

import { ImageError, ImageMeta } from '../models';
import { getEmptyImage } from './utils';

// The photograph slot an action is for; the upload, theme and submission
// reducers route the action to that slot by it.
export interface ImageTarget {
  themeId: number;
  submissionId: number;
  imageId: number;
}

const imageSlice = createSlice({
  name: 'upload/image',
  initialState: getEmptyImage,
  reducers: {
    imageInit: (state, action: PayloadAction<ImageMeta>) => ({
      ...state,
      meta: action.payload,
    }),
    imageStore: {
      reducer: (
        state,
        action: PayloadAction<
          { file: File | undefined; url: string; errors: ImageError },
          string,
          ImageTarget
        >,
      ) => ({
        ...state,
        meta: { ...state.meta, isChanged: true },
        ...action.payload,
      }),
      prepare: (
        themeId: number,
        submissionId: number,
        imageId: number,
        payload: { file: File | undefined; url: string; errors: ImageError },
      ) => ({ payload, meta: { themeId, submissionId, imageId } }),
    },
  },
});

export const { imageInit, imageStore } = imageSlice.actions;
export default imageSlice.reducer;
