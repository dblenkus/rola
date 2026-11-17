import axios from 'axios';

import { AppThunk } from '..';
import {
  addNotificationError,
  addNotificationSuccess,
  addNotificationWarning,
} from '../notifications/actions';

import { loadToken, rejectToken } from '../../services/token';
import { Contest, Theme } from '../../types/api';
import {
  ContestModel,
  DateChange,
  ImageMeta,
  InputChange,
  SubmissionMeta,
} from '../../types/models';
import imageReader from '../../utils/imageReader';
import upload, { SessionChanged } from '../../utils/upload';
import validate from '../../utils/validate';

import {
  AUTHOR_UPDATE,
  IMAGE_INIT,
  THEME_INIT,
  SUBMISSION_INIT,
  SUBMISSION_UPDATE,
  UPLOAD_COMPLETE,
  UPLOAD_INIT,
  UPLOAD_RESET,
  UPLOAD_SET_CONTEST,
  UPLOAD_SET_UPLOADING,
  UPLOAD_UNSET_UPLOADING,
  UploadActionTypes,
  IMAGE_STORE,
} from './types';

export const uploadInit = (
  contest: Contest,
  owner: string,
): UploadActionTypes => ({
  type: UPLOAD_INIT,
  payload: { contest, owner, uploadKey: crypto.randomUUID() },
});

// Tokens are never extended, and the photographs sent before a token
// expires mid-upload stay stored without a submission. An upload therefore
// starts only with a session that should outlast it.
const uploadSessionMargin = 60 * 60_000;

// Resolves to whether the photographs were uploaded.
export const uploadSubmit =
  (): AppThunk<Promise<boolean>> => async (dispatch, getState) => {
    const { contest, uploadKey } = getState().upload;
    if (uploadKey === null) {
      throw new Error('No upload form is open');
    }
    // Without a session the view sends the user to the login page, which
    // returns to this form.
    const session = loadToken();
    if (!session) {
      return false;
    }
    // Another account signed in before the view followed it; its form
    // opens next.
    if (session.email !== getState().upload.owner) {
      return false;
    }
    if (Date.parse(session.expires) - Date.now() < uploadSessionMargin) {
      rejectToken(`Token ${session.token}`);
      dispatch(
        addNotificationWarning(
          'Your session is about to expire. Please log in again.',
        ),
      );
      return false;
    }
    // The user may open another form while this one uploads; the outcome
    // of this upload must leave that form alone.
    const current = () => getState().upload.uploadKey === uploadKey;

    dispatch(uploadSetUploading());
    try {
      const newContest = await validate(contest);
      if (newContest.errors.hasError) {
        if (current()) {
          dispatch(uploadSetContest(newContest));
        }
        return false;
      }
      await upload(contest, session);
      if (current()) {
        dispatch(uploadComplete(uploadKey));
      }
      // The form's view may have been left or replaced during the upload.
      dispatch(
        addNotificationSuccess(
          `Your photographs for ${contest.meta.title} were uploaded.`,
        ),
      );
      return true;
    } catch (error) {
      // The view follows the changed session; there is nothing to report.
      if (error instanceof SessionChanged) {
        return false;
      }
      if (!axios.isAxiosError(error)) {
        throw error;
      }
      if (current()) {
        dispatch(addNotificationError('Upload failed. Please try again.'));
      }
      return false;
    } finally {
      if (current()) {
        dispatch(uploadUnsetUploading());
      }
    }
  };

export const uploadSetContest = (payload: ContestModel): UploadActionTypes => ({
  type: UPLOAD_SET_CONTEST,
  payload,
});

export const uploadReset = (): UploadActionTypes => ({
  type: UPLOAD_RESET,
});

export const uploadComplete = (uploadKey: string): UploadActionTypes => ({
  type: UPLOAD_COMPLETE,
  payload: { uploadKey },
});

export const uploadSetUploading = (): UploadActionTypes => ({
  type: UPLOAD_SET_UPLOADING,
});

export const uploadUnsetUploading = (): UploadActionTypes => ({
  type: UPLOAD_UNSET_UPLOADING,
});

export const authorUpdate = (
  payload: InputChange | DateChange,
): UploadActionTypes => ({
  type: AUTHOR_UPDATE,
  payload,
});

export const themeInit = (payload: Theme): UploadActionTypes => ({
  type: THEME_INIT,
  payload,
});

export const submissionInit = (payload: SubmissionMeta): UploadActionTypes => ({
  type: SUBMISSION_INIT,
  payload,
});

export const submissionUpdate = (
  theme_id: number,
  submission_id: number,
  payload: InputChange,
): UploadActionTypes => ({
  type: SUBMISSION_UPDATE,
  theme_id,
  submission_id,
  payload,
});

export const imageInit = (payload: ImageMeta): UploadActionTypes => ({
  type: IMAGE_INIT,
  payload,
});

export const imageStore = (
  theme_id: number,
  submission_id: number,
  image_id: number,
  payload: { file: File | undefined; url: string },
): UploadActionTypes => ({
  type: IMAGE_STORE,
  theme_id,
  submission_id,
  image_id,
  payload,
});

export const imageUpdate =
  (
    theme_id: number,
    submission_id: number,
    image_id: number,
    payload: { file: File | undefined },
  ): AppThunk<Promise<void>> =>
  async (dispatch) => {
    const { file } = payload;
    const url = !file ? '' : (await imageReader(file)).src;
    dispatch(imageStore(theme_id, submission_id, image_id, { file, url }));
  };
