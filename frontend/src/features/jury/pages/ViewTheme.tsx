import React, { useEffect, useState } from 'react';
import { Navigate, useParams } from 'react-router';
import { connect, ConnectedProps } from 'react-redux';

import { Alert, Typography } from '@mui/material';

import { AppState, AppDispatch } from '../../../app/store';

import {
  initializeStore,
  setSubmission,
  type InitializeResult,
} from '../state/actions';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import ThemeGallery from '../components/ThemeGallery';
import { contentUnavailable, requestError } from '../../../shared/api/errors';
import { Rating } from '../../../shared/api/types';
import fetchAll from '../../../shared/api/fetchAll';
import { getRatingsForTheme } from '../api';

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
  const [ratings, setRatings] = useState<Rating[]>([]);
  const [redirect, setRedirect] = useState<string | null>(null);
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
        if (result === 'missing') setError(contentUnavailable);
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

  if (redirect) return <Navigate to={redirect} />;

  const handleClick = (submissionId: number): void => {
    setSubmission(submissionId);
    setRedirect(
      `/judge/contest/${contestId}/theme/${themeId}/rate?submission=${submissionId}`,
    );
  };

  if (error) return <Alert severity="error">{error}</Alert>;

  if (!loaded || !submissions) return <LoadingProgress />;

  return (
    <>
      <Typography variant="h3" align="center" sx={{ marginBottom: 2 }}>
        {theme?.title}
      </Typography>
      <ThemeGallery
        submissions={submissions}
        isSeries={theme?.is_series || false}
        ratings={ratings}
        handleClick={handleClick}
      />
    </>
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
