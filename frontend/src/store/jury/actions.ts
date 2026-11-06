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

// Resolves to whether this initialization stored its theme.
export const initializeStore =
  (
    contestId: string,
    themeId: string,
    submissionId: number | undefined,
  ): AppThunk<Promise<boolean>> =>
  async (dispatch): Promise<boolean> => {
    initialization += 1;
    const current = initialization;
    try {
      const { data: contest } = await ContestService.getContest(contestId);
      const theme = contest.themes.find((t) => t.id.toString() === themeId);

      const submissionResource = () =>
        JudgeSubmissionService.getSubmissionsByTheme(parseInt(themeId, 10));
      const submissions = await fetchAll(submissionResource);

      let currentIndex = 0;
      if (submissionId) {
        currentIndex = submissions.findIndex((s) => s.id === submissionId);
        if (currentIndex === -1) currentIndex = 0;
      }

      if (!theme || current !== initialization) return false;
      dispatch(performInitialize(contest, theme, submissions, currentIndex));
      return true;
    } catch (error) {
      if (current === initialization) throw error;
      return false;
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
