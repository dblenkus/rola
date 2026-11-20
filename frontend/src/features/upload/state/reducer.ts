import { createSlice, isAnyOf, type PayloadAction } from '@reduxjs/toolkit';

import { Contest } from '../../../shared/api/types';
import { ContestMeta, ContestModel, ThemeModel } from '../models';

import authorReducer, { authorUpdate } from './reducerAuthor';
import { imageStore } from './reducerImage';
import { submissionUpdate } from './reducerSubmission';
import themeReducer, { themeInit } from './reducerTheme';
import { getEmptyContest } from './utils';

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
  endDate: contest.end_date,
  dateOfBirthRequired: contest.date_of_birth_required ?? false,
  clubVisible: contest.club_visible ?? false,
  clubRequired: contest.club_required ?? false,
  schoolVisible: contest.school_visible ?? false,
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

const uploadSlice = createSlice({
  name: 'upload',
  initialState,
  reducers: {
    uploadInit: {
      reducer: (
        state,
        action: PayloadAction<{
          contest: Contest;
          owner: string;
          uploadKey: string;
        }>,
      ) => {
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
      },
      prepare: (contest: Contest, owner: string) => ({
        payload: { contest, owner, uploadKey: crypto.randomUUID() },
      }),
    },
    uploadSetContest: (state, action: PayloadAction<ContestModel>) => ({
      ...state,
      contest: action.payload,
    }),
    uploadReset: () => initialState,
    uploadComplete: {
      reducer: (state, action: PayloadAction<{ uploadKey: string }>) => {
        // The upload may finish after another form replaced this one.
        if (action.payload.uploadKey !== state.uploadKey) {
          return state;
        }
        return { ...initialState, uploadedKey: action.payload.uploadKey };
      },
      prepare: (uploadKey: string) => ({ payload: { uploadKey } }),
    },
    uploadSetUploading: (state) => ({ ...state, uploading: true }),
    uploadUnsetUploading: (state) => ({ ...state, uploading: false }),
  },
  extraReducers: (builder) => {
    builder
      .addCase(authorUpdate, (state, action) => ({
        ...state,
        contest: {
          ...state.contest,
          author: authorReducer(state.contest.author, action),
        },
      }))
      .addMatcher(isAnyOf(submissionUpdate, imageStore), (state, action) => ({
        ...state,
        contest: {
          ...state.contest,
          themes: state.contest.themes.map((theme) => {
            return theme.meta.id === action.meta.themeId
              ? themeReducer(theme, action)
              : theme;
          }),
        },
      }));
  },
});

export const {
  uploadInit,
  uploadSetContest,
  uploadReset,
  uploadComplete,
  uploadSetUploading,
  uploadUnsetUploading,
} = uploadSlice.actions;
export default uploadSlice.reducer;
