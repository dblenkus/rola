import { AppState, AppThunk } from '../../../app/store';
import { JurySubmission } from '../../../shared/api/types';
import fetchAll from '../../../shared/api/fetchAll';

import { performInitialize } from './reducer';
import { getContest } from '../../contests/api';
import { getJurySubmissionsByTheme } from '../api';

export {
  performInitialize,
  setSubmission,
  setPreviousSubmission,
  setNextSubmission,
} from './reducer';

// Counts initializations, so that one that finishes after a newer one
// started neither replaces the newer theme nor reports its failure.
let initialization = 0;

// Whether this initialization stored its theme, was replaced by a newer one,
// or found the theme missing from the contest, as for a link whose contest id
// does not match its theme.
export type InitializeResult = 'stored' | 'superseded' | 'missing';

// Loads the theme and its submissions, and stores them with the position that
// `position` picks once they have arrived.
const loadTheme =
  (
    contestId: string,
    themeId: string,
    position: (submissions: JurySubmission[], state: AppState) => number,
  ): AppThunk<Promise<InitializeResult>> =>
  async (dispatch, getState): Promise<InitializeResult> => {
    initialization += 1;
    const current = initialization;
    try {
      const { data: contest } = await getContest(contestId);
      const theme = contest.themes.find((t) => t.id.toString() === themeId);
      if (!theme) return current === initialization ? 'missing' : 'superseded';

      const submissionResource = () =>
        getJurySubmissionsByTheme(parseInt(themeId, 10));
      const submissions = await fetchAll(submissionResource);

      if (current !== initialization) return 'superseded';
      const currentIndex = position(submissions, getState());
      dispatch(performInitialize(contest, theme, submissions, currentIndex));
      return 'stored';
    } catch (error) {
      if (current === initialization) throw error;
      return 'superseded';
    }
  };

const indexOf = (
  submissions: JurySubmission[],
  submissionId: number | undefined,
): number =>
  Math.max(
    submissions.findIndex((s) => s.id === submissionId),
    0,
  );

export const initializeStore = (
  contestId: string,
  themeId: string,
  submissionId: number | undefined,
): AppThunk<Promise<InitializeResult>> =>
  loadTheme(contestId, themeId, (submissions) =>
    indexOf(submissions, submissionId),
  );

// Loads the shown theme again and keeps the submission shown when the load
// finishes, which may not be the one shown when it started.
export const reloadStore = (
  contestId: string,
  themeId: string,
): AppThunk<Promise<InitializeResult>> =>
  loadTheme(contestId, themeId, (submissions, state) =>
    indexOf(submissions, getCurrentSubmission(state)?.id),
  );

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
