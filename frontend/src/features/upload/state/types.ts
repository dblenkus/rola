import { Contest, Theme } from '../../../shared/api/types';
import {
  ContestModel,
  DateChange,
  ImageError,
  ImageMeta,
  InputChange,
  SubmissionMeta,
} from '../models';

export interface UploadState {
  // The contest the form belongs to; null until it is opened for one.
  contestId: number | null;
  // The account that entered it; null until it is opened.
  owner: string | null;
  // Tells this form from a later one, which an upload that finishes after
  // the form was replaced must leave alone, and is the idempotency key, a
  // UUID, of its submissions; null until it is opened.
  uploadKey: string | null;
  // The form whose upload completed, for the view that showed it.
  uploadedKey: string | null;
  contest: ContestModel;
  uploading: boolean;
}

export const UPLOAD_INIT = 'UPLOAD_INIT';
export const UPLOAD_SET_CONTEST = 'UPLOAD_SET_CONTEST';
export const UPLOAD_RESET = 'UPLOAD_RESET';
export const UPLOAD_COMPLETE = 'UPLOAD_COMPLETE';
export const UPLOAD_SET_UPLOADING = 'UPLOAD_SET_UPLOADING';
export const UPLOAD_UNSET_UPLOADING = 'UPLOAD_UNSET_UPLOADING';
export const AUTHOR_UPDATE = 'AUTHOR_UPDATE';
export const THEME_INIT = 'THEME_INIT';
export const SUBMISSION_INIT = 'SUBMISSION_INIT';
export const SUBMISSION_UPDATE = 'SUBMISSION_UPDATE';
export const IMAGE_INIT = 'IMAGE_INIT';
export const IMAGE_STORE = 'IMAGE_STORE';

type UploadInitAction = {
  type: typeof UPLOAD_INIT;
  payload: { contest: Contest; owner: string; uploadKey: string };
};

type UploadSetContestAction = {
  type: typeof UPLOAD_SET_CONTEST;
  payload: ContestModel;
};

type UploadResetAction = {
  type: typeof UPLOAD_RESET;
};

type UploadCompleteAction = {
  type: typeof UPLOAD_COMPLETE;
  payload: { uploadKey: string };
};

type UploadStartUploadingAction = {
  type: typeof UPLOAD_SET_UPLOADING;
};

type UploadStopUploadingAction = {
  type: typeof UPLOAD_UNSET_UPLOADING;
};

type AuthorUpdateAction = {
  type: typeof AUTHOR_UPDATE;
  payload: InputChange | DateChange;
};

type ThemeInitAction = {
  type: typeof THEME_INIT;
  payload: Theme;
};

type SubmissionInitAction = {
  type: typeof SUBMISSION_INIT;
  payload: SubmissionMeta;
};

type SubmissionUpdateAction = {
  type: typeof SUBMISSION_UPDATE;
  theme_id: number;
  submission_id: number;
  payload: InputChange;
};

type ImageInitAction = {
  type: typeof IMAGE_INIT;
  payload: ImageMeta;
};

type ImageStoreAction = {
  type: typeof IMAGE_STORE;
  theme_id: number;
  submission_id: number;
  image_id: number;
  payload: { file: File | undefined; url: string; errors: ImageError };
};

export type UploadActionTypes =
  | UploadInitAction
  | UploadSetContestAction
  | UploadResetAction
  | UploadCompleteAction
  | UploadStartUploadingAction
  | UploadStopUploadingAction
  | AuthorUpdateAction
  | ThemeInitAction
  | SubmissionInitAction
  | SubmissionUpdateAction
  | ImageInitAction
  | ImageStoreAction;
