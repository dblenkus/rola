import { Contest } from '../../types/api';
import { ContestMeta, ThemeModel } from '../../types/models';

import {
  UPLOAD_COMPLETE,
  UPLOAD_INIT,
  UPLOAD_RESET,
  UPLOAD_SET_CONTEST,
  UPLOAD_SET_UPLOADING,
  UPLOAD_UNSET_UPLOADING,
  UploadActionTypes,
  UploadState,
} from './types';
import authorReducer from './reducerAuthor';
import themeReducer from './reducerTheme';
import { getEmptyContest } from './utils';
import { themeInit } from './actions';

const initialState: UploadState = {
  contestId: null,
  owner: null,
  uploadKey: null,
  uploadedKey: null,
  contest: getEmptyContest(),
  uploading: false,
};

const contestMeta = (contest: Contest): ContestMeta => ({
  title: contest.title,
  description: contest.description ?? '',
  noticeHtml: contest.notice_html ?? '',
  headerImage: contest.header_image ?? null,
  dobRequired: contest.dob_required ?? false,
  clubShow: contest.club_show ?? false,
  clubRequired: contest.club_required ?? false,
  schoolShow: contest.school_show ?? false,
  schoolRequired: contest.school_required ?? false,
});

// Whether a theme asks for as many submissions of as many photographs as
// before, so that what was entered for it still fits.
const sameSubmissions = (kept: ThemeModel, fresh: ThemeModel): boolean =>
  kept.submissions.length === fresh.submissions.length &&
  kept.submissions.every((submission, index) => {
    const meta = fresh.submissions[index]?.meta;
    return (
      meta !== undefined &&
      submission.meta.imageNumber === meta.imageNumber &&
      submission.meta.isSeries === meta.isSeries
    );
  });

const reducer = (
  state = initialState,
  action: UploadActionTypes,
): UploadState => {
  switch (action.type) {
    case UPLOAD_INIT: {
      const { contest, owner, uploadKey } = action.payload;
      const themes = contest.themes.map((theme) =>
        themeReducer(undefined, themeInit(theme)),
      );
      // The form is opened again after a forced re-login, for example; keep
      // what was entered for the same contest and account until it is
      // uploaded. Another account on this device starts an empty form.
      if (state.contestId === contest.id && state.owner === owner) {
        // The contest may have changed since the form was opened; show its
        // current fields and themes, keeping a theme's entries only while
        // they still fit it.
        return {
          ...state,
          contest: {
            ...state.contest,
            meta: contestMeta(contest),
            themes: themes.map((fresh) => {
              const kept = state.contest.themes.find(
                (theme) => theme.meta.id === fresh.meta.id,
              );
              return kept && sameSubmissions(kept, fresh)
                ? { ...kept, meta: fresh.meta }
                : fresh;
            }),
          },
        };
      }
      return {
        ...initialState,
        contestId: contest.id,
        owner,
        uploadKey,
        contest: { ...getEmptyContest(), meta: contestMeta(contest), themes },
      };
    }
    case UPLOAD_SET_CONTEST: {
      return { ...state, contest: action.payload };
    }
    case UPLOAD_RESET: {
      return initialState;
    }
    case UPLOAD_COMPLETE: {
      // The upload may finish after another form replaced this one.
      if (action.payload.uploadKey !== state.uploadKey) {
        return state;
      }
      return { ...initialState, uploadedKey: action.payload.uploadKey };
    }
    case UPLOAD_SET_UPLOADING: {
      return { ...state, uploading: true };
    }
    case UPLOAD_UNSET_UPLOADING: {
      return { ...state, uploading: false };
    }
    default: {
      let { themes } = state.contest;
      if ('theme_id' in action) {
        themes = themes.map((theme) => {
          return theme.meta.id === action.theme_id
            ? themeReducer(theme, action)
            : theme;
        });
      }
      return {
        ...state,
        contest: {
          ...state.contest,
          themes,
          author: authorReducer(state.contest.author, action),
        },
      };
    }
  }
};

export default reducer;
