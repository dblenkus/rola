import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

import { DateChange } from '../models';
import type { InputChange } from '../../../shared/ui/InputField';
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
