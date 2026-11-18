import { Contest, JurySubmission, Theme } from '../../../shared/api/types';

export interface JuryState {
  contest: Contest | null;
  theme: Theme | null;
  submissions: JurySubmission[] | null;
  currentIndex: number;
}

export const PERFORM_INITIALIZE = 'JURY_PERFORM_INITIALIZE';
export const SET_SUBMISSION = 'JURY_SET_SUBMISSION';
export const SET_PREVIOUS_SUBMISSION = 'JURY_SET_PREVIOUS_SUBMISSION';
export const SET_NEXT_SUBMISSION = 'JURY_SET_NEXT_SUBMISSION';

type PerformInitializeAction = {
  type: typeof PERFORM_INITIALIZE;
  payload: {
    contest: Contest;
    theme: Theme;
    submissions: JurySubmission[];
    currentIndex: number;
  };
};

type SetSubmissionAction = {
  type: typeof SET_SUBMISSION;
  payload: { submissionId: number };
};

type SetPreviousSubmissionAction = {
  type: typeof SET_PREVIOUS_SUBMISSION;
};

type SetNextSubmissionAction = {
  type: typeof SET_NEXT_SUBMISSION;
};

export type JuryActionTypes =
  | PerformInitializeAction
  | SetSubmissionAction
  | SetPreviousSubmissionAction
  | SetNextSubmissionAction;
