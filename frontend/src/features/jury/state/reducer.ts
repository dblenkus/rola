import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

import { Contest, JurySubmission, Theme } from '../../../shared/api/types';

export interface JuryState {
  contest: Contest | null;
  theme: Theme | null;
  submissions: JurySubmission[] | null;
  currentIndex: number;
}

const initialState: JuryState = {
  contest: null,
  theme: null,
  submissions: null,
  currentIndex: 0,
};

const jurySlice = createSlice({
  name: 'jury',
  initialState,
  reducers: {
    performInitialize: {
      reducer: (
        state,
        action: PayloadAction<{
          contest: Contest;
          theme: Theme;
          submissions: JurySubmission[];
          currentIndex: number;
        }>,
      ) => ({ ...state, ...action.payload }),
      prepare: (
        contest: Contest,
        theme: Theme,
        submissions: JurySubmission[],
        currentIndex: number,
      ) => ({ payload: { contest, theme, submissions, currentIndex } }),
    },
    setSubmission: {
      reducer: (state, action: PayloadAction<{ submissionId: number }>) => {
        const { submissions } = state;
        const { submissionId } = action.payload;
        const newIndex =
          submissions?.findIndex((s) => s.id === submissionId) ?? -1;
        state.currentIndex = Math.max(newIndex, 0);
      },
      prepare: (submissionId: number) => ({ payload: { submissionId } }),
    },
    // A move requested before a reload changed the list stays within it.
    setPreviousSubmission: (state) => {
      state.currentIndex = Math.max(state.currentIndex - 1, 0);
    },
    setNextSubmission: (state) => {
      state.currentIndex = Math.min(
        state.currentIndex + 1,
        Math.max((state.submissions?.length ?? 0) - 1, 0),
      );
    },
  },
});

export const {
  performInitialize,
  setSubmission,
  setPreviousSubmission,
  setNextSubmission,
} = jurySlice.actions;
export default jurySlice.reducer;
