import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

import { ImageError, ImageMeta, ImageSize } from '../models';
import { getEmptyImage } from './utils';

// The photograph slot an action is for; the upload, theme and submission
// reducers route the action to that slot by it.
export interface ImageTarget {
  themeId: number;
  submissionId: number;
  imageId: number;
}

// What a photograph slot holds after a choice: the file, its preview, the
// problem reading it, and its pixel size once the browser decoded it.
export interface ImageChoice {
  file: File | undefined;
  url: string;
  errors: ImageError;
  size?: ImageSize;
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
        action: PayloadAction<ImageChoice, string, ImageTarget>,
      ) => {
        const { file, url, errors, size } = action.payload;
        // The size belongs to the photograph it was measured on, so a choice
        // without one (a removal, an unreadable file) clears it.
        return {
          ...state,
          meta: { ...state.meta, isChanged: true },
          file,
          url,
          errors,
          size,
        };
      },
      prepare: (
        themeId: number,
        submissionId: number,
        imageId: number,
        payload: ImageChoice,
      ) => ({ payload, meta: { themeId, submissionId, imageId } }),
    },
  },
});

export const { imageInit, imageStore } = imageSlice.actions;
export default imageSlice.reducer;
