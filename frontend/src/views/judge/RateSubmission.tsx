import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, useLocation, useParams, Navigate } from 'react-router';
import { connect, ConnectedProps } from 'react-redux';

import { Alert } from '@mui/material';

import SubmissionRater from '../../components/Jury/SubmissionRater';

import { AppState, AppDispatch } from '../../store';

import {
  getCurrentSubmission,
  getIsNext,
  getIsPrevious,
  initializeStore,
  reloadStore,
  setNextSubmission,
  setPreviousSubmission,
  type InitializeResult,
} from '../../store/jury/actions';
import RatingService from '../../services/RatingService';
import { contentUnavailable, requestError } from '../../services/errors';
import useKeyPress from '../../hooks/useKeyPress';
import LoadingProgress from '../../components/LoadingProgress';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

const RateSubmission: React.FC<PropsFromRedux> = ({
  submission: storedSubmission,
  theme,
  isPrevious: storedIsPrevious,
  isNext: storedIsNext,
  initialize,
  reload,
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
  // A failed reload of the photograph links keeps the rater as it was. It is
  // kept with the submissions whose photographs failed, each until one of its
  // photographs loads or a later reload succeeds.
  const [reloadError, setReloadError] = useState<{
    submissionIds: ReadonlySet<number>;
    message: string;
  } | null>(null);
  const [close, setClose] = useState(false);
  // Until this view's own initialization has stored its theme, the store
  // holds the theme opened before, or this one as it was; none of it may be
  // shown, rated or put in the address.
  const [loaded, setLoaded] = useState(false);

  const { contestId, themeId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  if (!themeId) {
    throw new Error('Missing themeId route parameter');
  }
  const submission = loaded ? storedSubmission : null;
  const isPrevious = loaded && storedIsPrevious;
  const isNext = loaded && storedIsNext;

  const navigate = useNavigate();
  const location = useLocation();
  const submissionId = useRef(
    Number(new URLSearchParams(location.search).get('submission')) || undefined,
  );

  // The submission on screen, for saves that finish after the judge moved on.
  // Cleared when the rater closes: the jury store outlives it, and a save that
  // finishes later must not move the next rater on.
  const shownId = useRef<number | undefined>(undefined);
  useEffect(() => {
    shownId.current = submission?.id;
    return () => {
      shownId.current = undefined;
    };
  }, [submission]);

  // One save at a time: the server keeps whichever save it handles last, so a
  // rating sent while another is pending could be overwritten by it. The ref
  // guards the keys and any input before the disabled stars render.
  const saveInProgress = useRef(false);
  const [saving, setSaving] = useState(false);

  const updateRating = async (newRating: number): Promise<void> => {
    if (!submission || saveInProgress.current) return;
    const ratedId = submission.id;
    saveInProgress.current = true;
    setSaving(true);
    setSaveError(null);
    try {
      await RatingService.updateForSubmission(ratedId, newRating);
    } catch (error) {
      setSaveError({ submissionId: ratedId, message: requestError(error) });
      return;
    } finally {
      saveInProgress.current = false;
      setSaving(false);
    }
    // A judge who moved on stays where they are; the rating is fetched again
    // when they return.
    if (shownId.current !== ratedId) return;
    setRating({ submissionId: ratedId, value: newRating });
    if (isNext) nextSubmission();
  };

  // Initialize the store.
  useEffect(() => {
    initialize(contestId, themeId, submissionId.current)
      .then((result) => {
        if (result === 'missing') setError(contentUnavailable);
        else setLoaded(result === 'stored');
      })
      .catch((error: unknown) => setError(requestError(error)));
  }, [contestId, themeId, initialize]);

  // Photograph links are signed for an hour, and a judge can spend longer on
  // a theme. A photograph that fails to load reloads the theme for new links
  // at most once a minute, so that one missing for another reason does not
  // reload it over and over.
  const lastReload = useRef<number | undefined>(undefined);
  // Submissions whose photographs failed since the last stored reload,
  // including those the throttle or a pending reload kept from reloading, so
  // that a failed reload is shown on all of them.
  const failedIds = useRef(new Set<number>());
  const reloadSubmissions = () => {
    if (!submission) return;
    failedIds.current.add(submission.id);
    const now = Date.now();
    if (lastReload.current !== undefined && now - lastReload.current <= 60_000)
      return;
    lastReload.current = now;
    // A stored reload keeps the submission on screen and gives it new links;
    // one that a newer initialization replaced changes nothing.
    reload(contestId, themeId)
      .then((result) => {
        if (result === 'missing') setError(contentUnavailable);
        else {
          failedIds.current.clear();
          setReloadError(null);
        }
      })
      .catch((error: unknown) => {
        // Nothing was reloaded, so the next failing photograph tries again.
        lastReload.current = undefined;
        setReloadError({
          submissionIds: new Set(failedIds.current),
          message: requestError(error),
        });
      });
  };

  const photographLoaded = (loadedId: number) => {
    failedIds.current.delete(loadedId);
    setReloadError((current) => {
      if (!current?.submissionIds.has(loadedId)) return current;
      const submissionIds = new Set(current.submissionIds);
      submissionIds.delete(loadedId);
      return submissionIds.size > 0 ? { ...current, submissionIds } : null;
    });
  };

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

  useKeyPress((value: string, repeat: boolean) => {
    // Without a loaded theme the rater is hidden; keys must not rate it.
    if (error) return;
    const parsedNumber = parseInt(value, 10);
    if (!Number.isNaN(parsedNumber)) {
      // A held digit repeats, and each repeat would rate the photograph the
      // last save moved on to before the judge has seen it. Held arrow keys
      // only step through the photographs, so they keep repeating.
      if (!repeat) updateRating(parsedNumber || 10);
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

  if (!submission) return <LoadingProgress />;

  return (
    <>
      {saveError?.submissionId === submission.id && (
        <Alert severity="error">{saveError.message}</Alert>
      )}
      {reloadError?.submissionIds.has(submission.id) && (
        <Alert severity="error">{reloadError.message}</Alert>
      )}
      <SubmissionRater
        submission={submission}
        rating={rating?.submissionId === submission.id ? rating.value : 0}
        ratingDisabled={saving}
        isSeries={theme?.is_series || false}
        close={handleClose}
        isPrevious={isPrevious}
        isNext={isNext}
        previousSubmission={previousSubmission}
        nextSubmission={nextSubmission}
        updateRating={updateRating}
        onImageError={reloadSubmissions}
        onImageLoad={() => photographLoaded(submission.id)}
      />
      {/* A rating saved since the failed load replaces the missing one. */}
      {loadError?.submissionId === submission.id &&
        rating?.submissionId !== submission.id && (
          <Alert severity="error">{loadError.message}</Alert>
        )}
    </>
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
  ): Promise<InitializeResult> =>
    dispatch(initializeStore(contestId, themeId, submissionId)),
  reload: (contestId: string, themeId: string): Promise<InitializeResult> =>
    dispatch(reloadStore(contestId, themeId)),
  previousSubmission: () => dispatch(setPreviousSubmission()),
  nextSubmission: () => dispatch(setNextSubmission()),
});

const connector = connect(mapStateToProps, mapDispatchToProps);

type PropsFromRedux = ConnectedProps<typeof connector>;

const ConnectedRateSubmission = connector(RateSubmission);

// Another theme gets a new view, so no state of the previous one stays.
const RateSubmissionRoute: React.FC = () => {
  const { contestId, themeId } = useParams<keyof RouteMatchParams>();
  return <ConnectedRateSubmission key={`${contestId}/${themeId}`} />;
};

export default RateSubmissionRoute;
