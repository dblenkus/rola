import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router';
import { connect, ConnectedProps } from 'react-redux';
import { useTranslation } from 'react-i18next';

import { AppState, AppDispatch } from '../../../app/store';

import {
  initializeStore,
  setSubmission,
  type InitializeResult,
} from '../state/actions';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import ScoringProgress from '../components/ScoringProgress';
import ThemeGallery from '../components/ThemeGallery';
import { contentUnavailable, requestError } from '../../../shared/api/errors';
import { Rating } from '../../../shared/api/types';
import fetchAll from '../../../shared/api/fetchAll';
import { getRatingsForTheme } from '../api';
import './ViewTheme.css';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

const ViewTheme: React.FC<PropsFromRedux> = ({
  initialize,
  setSubmission,
  theme,
  submissions,
}: PropsFromRedux) => {
  const [error, setError] = useState<string | null>(null);
  // Until this view's own initialization has stored its theme, the store
  // holds the theme opened before, or this one as it was.
  const [loaded, setLoaded] = useState(false);
  // Until they arrive, no photo is shown as unscored.
  const [ratings, setRatings] = useState<Rating[] | null>(null);
  const { t } = useTranslation();
  const { contestId, themeId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  if (!themeId) {
    throw new Error('Missing themeId route parameter');
  }

  // Initialize the store.
  useEffect(() => {
    initialize(contestId, themeId)
      .then((result) => {
        if (result === 'missing') setError(contentUnavailable());
        else setLoaded(result === 'stored');
      })
      .catch((error: unknown) => setError(requestError(error)));
  }, [contestId, themeId, initialize]);

  // Fetch ratings.
  useEffect(() => {
    const fetchRatings = async (): Promise<void> => {
      const ratingResource = () => getRatingsForTheme(parseInt(themeId, 10));
      setRatings(await fetchAll(ratingResource));
    };
    fetchRatings().catch((error: unknown) => setError(requestError(error)));
  }, [themeId]);

  const raterLink = (submissionId: number): string =>
    `/judge/contest/${contestId}/theme/${themeId}/rate?submission=${submissionId}`;

  if (error) return <Message severity="error">{error}</Message>;

  if (!loaded || !submissions || !theme || !ratings) return <LoadingProgress />;

  const scored = submissions.filter(({ id }) =>
    ratings.some((rating) => rating.submission === id),
  ).length;

  return (
    <Page title={theme.title}>
      <div className="jury-view__progress">
        <ScoringProgress
          scored={scored}
          total={submissions.length}
          caption={t('jury_scored')}
          label={t('jury_progress', {
            scored,
            total: submissions.length,
          })}
        />
      </div>
      {submissions.length ? (
        <ThemeGallery
          submissions={submissions}
          ratings={ratings}
          raterLink={raterLink}
          onOpen={setSubmission}
        />
      ) : (
        <p className="body jury-view__empty">{t('jury_no_submissions')}</p>
      )}
    </Page>
  );
};

const mapStateToProps = (state: AppState) => ({ ...state.jury });

const mapDispatchToProps = (dispatch: AppDispatch) => ({
  initialize: (contestId: string, themeId: string): Promise<InitializeResult> =>
    dispatch(initializeStore(contestId, themeId, undefined)),
  setSubmission: (submissionId: number): void => {
    dispatch(setSubmission(submissionId));
  },
});

const connector = connect(mapStateToProps, mapDispatchToProps);

type PropsFromRedux = ConnectedProps<typeof connector>;

const ConnectedViewTheme = connector(ViewTheme);

// Another theme gets a new view, so no state of the previous one stays.
const ViewThemeRoute: React.FC = () => {
  const { contestId, themeId } = useParams<keyof RouteMatchParams>();
  return <ConnectedViewTheme key={`${contestId}/${themeId}`} />;
};

export default ViewThemeRoute;
