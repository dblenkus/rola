import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, useLocation, useParams, Navigate } from 'react-router';
import { connect, ConnectedProps } from 'react-redux';
import _ from 'lodash';

import { Alert } from '@mui/material';

import SubmissionRater from '../../components/Jury/SubmissionRater';

import { AppState, AppDispatch } from '../../store';

import {
  getCurrentSubmission,
  getIsNext,
  getIsPrevious,
  initializeStore,
  setNextSubmission,
  setPreviousSubmission,
} from '../../store/jury/actions';
import RatingService from '../../services/RatingService';
import { requestError } from '../../services/errors';
import useKeyPress from '../../hooks/useKeyPress';
import LoadingProgress from '../../components/LoadingProgress';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

const RateSubmission: React.FC<PropsFromRedux> = ({
  submission,
  theme,
  isLoading,
  isPrevious,
  isNext,
  initialize,
  nextSubmission,
  previousSubmission,
}: PropsFromRedux) => {
  const [error, setError] = useState<string | null>(null);
  // A failed rating load is kept with its submission and leaves the rater
  // usable; the rating is fetched again when the judge returns to it.
  const [loadError, setLoadError] = useState<{
    submissionId: number;
    message: string;
  } | null>(null);
  // Kept with its submission, so another submission never shows it.
  const [rating, setRating] = useState<{
    submissionId: number;
    value: number;
  } | null>(null);
  // A failed save keeps the rater on screen so the judge can try again.
  const [saveError, setSaveError] = useState<{
    submissionId: number;
    message: string;
  } | null>(null);
  const [close, setClose] = useState(false);

  const { contestId, themeId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  if (!themeId) {
    throw new Error('Missing themeId route parameter');
  }

  const navigate = useNavigate();
  const location = useLocation();
  const submissionId = useRef(
    Number(new URLSearchParams(location.search).get('submission')) || undefined,
  );

  // The submission on screen, for saves that finish after the judge moved on.
  const shownId = useRef<number | undefined>(undefined);
  useEffect(() => {
    shownId.current = submission?.id;
  }, [submission]);

  const updateRating = async (newRating: number): Promise<void> => {
    if (!submission) return;
    const ratedId = submission.id;
    setSaveError(null);
    try {
      await RatingService.updateForSubmission(ratedId, newRating);
    } catch (error) {
      setSaveError({ submissionId: ratedId, message: requestError(error) });
      return;
    }
    // A judge who moved on stays where they are; the rating is fetched again
    // when they return.
    if (shownId.current !== ratedId) return;
    setRating({ submissionId: ratedId, value: newRating });
    if (isNext) nextSubmission();
  };

  // Initialize the store.
  useEffect(() => {
    initialize(contestId, themeId, submissionId.current).catch(
      (error: unknown) => setError(requestError(error)),
    );
  }, [contestId, themeId, initialize]);

  // Store submission id in url.
  useEffect(() => {
    if (submission && submissionId.current !== submission.id) {
      navigate(`?submission=${submission.id}`);
      submissionId.current = submission.id;
    }
  }, [navigate, submission]);

  const currentId = submission?.id;
  useEffect(() => {
    if (currentId === undefined) return;
    // Judges move on before slow responses arrive; drop the ones they left.
    let active = true;
    RatingService.getForSubmission(currentId)
      .then(({ data: ratings }) => {
        if (active) {
          setRating({
            submissionId: currentId,
            value: ratings.results[0]?.rating ?? 0,
          });
          setLoadError(null);
        }
      })
      .catch((error: unknown) => {
        if (active) {
          setLoadError({
            submissionId: currentId,
            message: requestError(error),
          });
        }
      });
    return () => {
      active = false;
    };
  }, [currentId]);

  useKeyPress((value: string) => {
    // Without a loaded theme the rater is hidden; keys must not rate it.
    if (error) return;
    const parsedNumber = parseInt(value, 10);
    if (!_.isNaN(parsedNumber)) {
      updateRating(parsedNumber || 10);
    } else if (value === 'ArrowRight' && isNext) {
      nextSubmission();
    } else if (value === 'ArrowLeft' && isPrevious) {
      previousSubmission();
    }
  });

  const handleClose = () => setClose(true);

  if (close)
    return <Navigate to={`/judge/contest/${contestId}/theme/${themeId}`} />;

  if (error) return <Alert severity="error">{error}</Alert>;

  if (isLoading || !submission) return <LoadingProgress />;

  return (
    <div style={{ position: 'absolute', width: '100%', left: 0, right: 0 }}>
      {saveError?.submissionId === submission.id && (
        <Alert severity="error">{saveError.message}</Alert>
      )}
      <SubmissionRater
        submission={submission}
        rating={rating?.submissionId === submission.id ? rating.value : 0}
        isSeries={theme?.is_series || false}
        close={handleClose}
        isPrevious={isPrevious}
        isNext={isNext}
        previousSubmission={previousSubmission}
        nextSubmission={nextSubmission}
        updateRating={updateRating}
      />
      {/* A rating saved since the failed load replaces the missing one. */}
      {loadError?.submissionId === submission.id &&
        rating?.submissionId !== submission.id && (
          <Alert severity="error">{loadError.message}</Alert>
        )}
    </div>
  );
};

const mapStateToProps = (state: AppState) => ({
  ...state.jury,
  submission: getCurrentSubmission(state),
  isPrevious: getIsPrevious(state),
  isNext: getIsNext(state),
});

const mapDispatchToProps = (dispatch: AppDispatch) => ({
  initialize: (
    contestId: string,
    themeId: string,
    submissionId: number | undefined,
  ): Promise<void> =>
    dispatch(initializeStore(contestId, themeId, submissionId)),
  previousSubmission: () => dispatch(setPreviousSubmission()),
  nextSubmission: () => dispatch(setNextSubmission()),
});

const connector = connect(mapStateToProps, mapDispatchToProps);

type PropsFromRedux = ConnectedProps<typeof connector>;

export default connector(RateSubmission);
