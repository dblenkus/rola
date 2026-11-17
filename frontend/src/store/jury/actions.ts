import { AppState, AppThunk } from '..';
import ContestService from '../../services/ContestService';
import JudgeSubmissionService from '../../services/JudgeSubmissionService';
import { Contest, JurySubmission, Theme } from '../../types/api';
import fetchAll from '../../utils/fetchAll';

import {
  JuryActionTypes,
  PERFORM_INITIALIZE,
  SET_SUBMISSION,
  SET_PREVIOUS_SUBMISSION,
  SET_NEXT_SUBMISSION,
} from './types';

export const performInitialize = (
  contest: Contest,
  theme: Theme,
  submissions: JurySubmission[],
  currentIndex: number,
): JuryActionTypes => ({
  type: PERFORM_INITIALIZE,
  payload: { contest, theme, submissions, currentIndex },
});

export const setSubmission = (submissionId: number): JuryActionTypes => ({
  type: SET_SUBMISSION,
  payload: { submissionId },
});
export const setPreviousSubmission = (): JuryActionTypes => ({
  type: SET_PREVIOUS_SUBMISSION,
});
export const setNextSubmission = (): JuryActionTypes => ({
  type: SET_NEXT_SUBMISSION,
});

// Counts initializations, so that one that finishes after a newer one
// started neither replaces the newer theme nor reports its failure.
let initialization = 0;

// Whether this initialization stored its theme, was replaced by a newer one,
// or found the theme missing from the contest, as for a link whose contest id
// does not match its theme.
export type InitializeResult = 'stored' | 'superseded' | 'missing';

export const initializeStore =
  (
    contestId: string,
    themeId: string,
    submissionId: number | undefined,
  ): AppThunk<Promise<InitializeResult>> =>
  async (dispatch): Promise<InitializeResult> => {
    initialization += 1;
    const current = initialization;
    try {
      const { data: contest } = await ContestService.getContest(contestId);
      const theme = contest.themes.find((t) => t.id.toString() === themeId);
      if (!theme) return current === initialization ? 'missing' : 'superseded';

      const submissionResource = () =>
        JudgeSubmissionService.getSubmissionsByTheme(parseInt(themeId, 10));
      const submissions = await fetchAll(submissionResource);

      let currentIndex = 0;
      if (submissionId) {
        currentIndex = submissions.findIndex((s) => s.id === submissionId);
        if (currentIndex === -1) currentIndex = 0;
      }

      if (current !== initialization) return 'superseded';
      dispatch(performInitialize(contest, theme, submissions, currentIndex));
      return 'stored';
    } catch (error) {
      if (current === initialization) throw error;
      return 'superseded';
    }
  };

export const getCurrentSubmission = (
  state: AppState,
): JurySubmission | null => {
  const {
    jury: { submissions, currentIndex },
  } = state;

  if (!submissions) return null;
  return submissions[currentIndex] ?? null;
};

export const getIsPrevious = (state: AppState): boolean => {
  const {
    jury: { submissions, currentIndex },
  } = state;

  if (!submissions) return false;
  return currentIndex > 0;
};

export const getIsNext = (state: AppState): boolean => {
  const {
    jury: { submissions, currentIndex },
  } = state;

  if (!submissions) return false;
  return submissions.length > currentIndex + 1;
};
