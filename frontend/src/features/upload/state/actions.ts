import axios from 'axios';

import { AppThunk } from '../../../app/store';
import {
  addNotificationError,
  addNotificationInfo,
  addNotificationSuccess,
  addNotificationWarning,
} from '../../notifications';

import i18n from '../../../app/i18n/config';
import {
  authorizationHeader,
  loadToken,
  rejectToken,
} from '../../../shared/api/token';
import imageReader from '../utils/imageReader';
import upload, { SessionChanged } from '../utils/upload';
import validate from '../utils/validate';

import {
  uploadComplete,
  uploadSetContest,
  uploadSetUploading,
  uploadUnsetUploading,
} from './reducer';
import { imageStore } from './reducerImage';
import { getEmptyImageError } from './utils';

export {
  uploadComplete,
  uploadInit,
  uploadReset,
  uploadSetContest,
  uploadSetUploading,
  uploadUnsetUploading,
} from './reducer';
export { authorUpdate } from './reducerAuthor';
export { imageInit, imageStore } from './reducerImage';
export { submissionInit, submissionUpdate } from './reducerSubmission';
export { themeInit } from './reducerTheme';

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
      rejectToken(authorizationHeader(session.token));
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
      const alreadyStored = await upload(contest, session, uploadKey);
      if (current()) {
        dispatch(uploadComplete(uploadKey));
      }
      if (alreadyStored) {
        // An earlier attempt was stored although its response was lost;
        // changes made to the form since then were not applied.
        dispatch(addNotificationInfo(i18n.t('upload_already_received')));
      } else {
        // The form's view may have been left or replaced during the upload.
        dispatch(
          addNotificationSuccess(
            `Your photographs for ${contest.meta.title} were uploaded.`,
          ),
        );
      }
      return true;
    } catch (error) {
      // The view follows the changed session; there is nothing to report.
      if (error instanceof SessionChanged) {
        return false;
      }
      if (!axios.isAxiosError(error)) {
        throw error;
      }
      // The server checks the contest's entry window when the submissions
      // are created, and the contest may have closed since the form opened.
      const closed =
        error.config?.url === '/submission' && error.response?.status === 403;
      if (current()) {
        dispatch(
          addNotificationError(
            closed
              ? 'The contest is closed. Your photographs were not submitted.'
              : 'Upload failed. Please try again.',
          ),
        );
      }
      return false;
    } finally {
      if (current()) {
        dispatch(uploadUnsetUploading());
      }
    }
  };

// Counts the choices made for each photograph slot of each form. Reading a
// large photograph takes long enough for the user to remove it or choose
// another, and only the latest choice may fill the slot.
const imageChoices = new Map<string, number>();

export const imageUpdate =
  (
    theme_id: number,
    submission_id: number,
    image_id: number,
    payload: { file: File | undefined },
  ): AppThunk<Promise<void>> =>
  async (dispatch, getState) => {
    const { file } = payload;
    const { uploadKey } = getState().upload;
    const slot = `${uploadKey}:${theme_id}:${submission_id}:${image_id}`;
    const choice = (imageChoices.get(slot) ?? 0) + 1;
    imageChoices.set(slot, choice);
    let url = '';
    let errors = getEmptyImageError();
    if (file) {
      try {
        url = (await imageReader(file)).src;
      } catch {
        // The browser cannot decode it, for example HEIC data saved as .jpg.
        // The slot takes the file with the error rather than keeping an
        // earlier choice the entrant meant to replace.
        errors = { file: 'Invalid file.', hasError: true };
      }
    }
    // A later choice, or another form, replaced this one during the read.
    if (
      imageChoices.get(slot) !== choice ||
      getState().upload.uploadKey !== uploadKey
    ) {
      return;
    }
    dispatch(
      imageStore(theme_id, submission_id, image_id, { file, url, errors }),
    );
  };
