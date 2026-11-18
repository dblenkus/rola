import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

import { DateChange, InputChange } from '../models';
import { getEmptyAuthor } from './utils';

const authorSlice = createSlice({
  name: 'upload/author',
  initialState: getEmptyAuthor,
  reducers: {
    authorUpdate: (state, action: PayloadAction<InputChange | DateChange>) => {
      const { name, value } = action.payload;
      return {
        ...state,
        [name]: value,
      };
    },
  },
});

export const { authorUpdate } = authorSlice.actions;
export default authorSlice.reducer;
