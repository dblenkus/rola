import { Contest, Submission, Theme } from '../../types/api';

export interface JuryState {
    isLoading: boolean;
    contest: Contest | null;
    theme: Theme | null;
    submissions: Submission[] | null;
    currentIndex: number;
}

export const PERFORM_INITIALIZE = 'JURY_PERFORM_INITIALIZE';
export const SET_SUBMISSION = 'JURY_SET_SUBMISSION';
export const SET_PREVIOUS_SUBMISSION = 'JURY_SET_PREVIOUS_SUBMISSION';
export const SET_NEXT_SUBMISSION = 'JURY_SET_NEXT_SUBMISSION';

interface PerformInitializeAction {
    type: typeof PERFORM_INITIALIZE;
    payload: {
        contest: Contest;
        theme: Theme;
        submissions: Submission[];
        currentIndex: number;
    };
}

interface SetSubmissionAction {
    type: typeof SET_SUBMISSION;
    payload: { submissionId: number };
}

interface SetPreviousSubmissionAction {
    type: typeof SET_PREVIOUS_SUBMISSION;
}

interface SetNextSubmissionAction {
    type: typeof SET_NEXT_SUBMISSION;
}

export type JuryActionTypes =
    | PerformInitializeAction
    | SetSubmissionAction
    | SetPreviousSubmissionAction
    | SetNextSubmissionAction;
