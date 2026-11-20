import React, { useEffect, useRef, useState, type ReactNode } from 'react';
import { useNavigate, useLocation, useParams } from 'react-router';
import { connect, ConnectedProps } from 'react-redux';
import { useTranslation } from 'react-i18next';

import Filmstrip from '../components/Filmstrip';
import JudgeBar from '../components/JudgeBar';
import PhotoLabel from '../components/PhotoLabel';
import PhotoNavigation from '../components/PhotoNavigation';
import Photographs from '../components/Photographs';
import ScorePad from '../components/ScorePad';
import ShortcutLegend from '../components/ShortcutLegend';
import photoId from '../components/photoId';
import {
  loadShortcutsOn,
  storeShortcutsOn,
} from '../components/shortcutsSetting';

import { AppState, AppDispatch } from '../../../app/store';

import {
  getCurrentSubmission,
  getIsNext,
  getIsPrevious,
  initializeStore,
  reloadStore,
  setNextSubmission,
  setPreviousSubmission,
  setSubmission,
  type InitializeResult,
} from '../state/actions';
import { contentUnavailable, requestError } from '../../../shared/api/errors';
import fetchAll from '../../../shared/api/fetchAll';
import useKeyPress from '../../../shared/hooks/useKeyPress';
import usePageTitle from '../../../shared/hooks/usePageTitle';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import {
  deleteRating,
  getRatingsForSubmission,
  getRatingsForTheme,
  updateRatingForSubmission,
} from '../api';
import './RateSubmission.css';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

// A rating the judge has given: its id, which clearing it needs, and its
// score.
interface StoredRating {
  id: number;
  value: number;
}

// What the status region last said, by what the judge did. A move is put in
// words once the new photograph's own rating has loaded or failed to.
type Announced =
  { kind: 'score'; value: number } | { kind: 'cleared' } | { kind: 'moved' };

// The theme's ratings as loaded, with what the view learned since in their
// place.
function withLearned(
  ratings: ReadonlyMap<number, StoredRating>,
  learned: ReadonlyMap<number, StoredRating | null>,
): ReadonlyMap<number, StoredRating> {
  const updated = new Map(ratings);
  for (const [submissionId, saved] of learned) {
    if (saved) updated.set(submissionId, saved);
    else updated.delete(submissionId);
  }
  return updated;
}

const RateSubmission: React.FC<PropsFromRedux> = ({
  submission: storedSubmission,
  contest: storedContest,
  theme: storedTheme,
  submissions: storedSubmissions,
  currentIndex,
  isPrevious: storedIsPrevious,
  isNext: storedIsNext,
  initialize,
  reload,
  nextSubmission,
  previousSubmission,
  selectSubmission,
}: PropsFromRedux) => {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);
  // A failed rating load is kept with its submission and leaves the rater
  // usable; the rating is fetched again when the judge returns to it.
  const [loadError, setLoadError] = useState<{
    submissionId: number;
    message: string;
  } | null>(null);
  // Kept with its submission, so another submission never shows it. `saved`
  // is null while the submission has no rating. A write that finishes after
  // the judge moved on still updates it, so a return shows the result.
  const [rating, setRating] = useState<{
    submissionId: number;
    saved: StoredRating | null;
  } | null>(null);
  // A failed save or clear keeps the rater on screen so the judge can try
  // again.
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
  // The judge's ratings across the theme, by submission, for the count and
  // the frames. Null until they load, and for good if they fail: the rater
  // works without them, leaving out the count and the frames' scores.
  const [themeRatings, setThemeRatings] = useState<ReadonlyMap<
    number,
    StoredRating
  > | null>(null);
  // Each submission's rating as this view's own reads and writes found it,
  // null for none. The theme's ratings are requested before any of them, so
  // these replace what that request answers, whenever it answers.
  const [learned, setLearned] = useState<
    ReadonlyMap<number, StoredRating | null>
  >(new Map());
  const [announced, setAnnounced] = useState<{
    count: number;
    event: Announced;
  } | null>(null);
  const [shortcutsOn, setShortcutsOn] = useState(loadShortcutsOn);
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
  const submissions = loaded ? storedSubmissions : null;
  const contest = loaded ? storedContest : null;
  const theme = loaded ? storedTheme : null;
  const isPrevious = loaded && storedIsPrevious;
  const isNext = loaded && storedIsNext;

  usePageTitle(theme?.title ?? '');

  const navigate = useNavigate();
  const location = useLocation();
  const submissionId = useRef(
    Number(new URLSearchParams(location.search).get('submission')) || undefined,
  );

  // The submission on screen, for writes that finish after the judge moved
  // on.
  const shownId = useRef<number | undefined>(undefined);
  useEffect(() => {
    shownId.current = submission?.id;
  }, [submission]);

  const announce = (event: Announced) =>
    setAnnounced((current) => ({ count: (current?.count ?? 0) + 1, event }));

  // One write at a time for each submission, a save or a clear: the server
  // keeps whichever write for a rating it handles last, so a write sent while
  // another for the same submission is pending could be overwritten by it.
  // Writes for different submissions do not conflict. The ref guards the
  // keys and any input before the disabled score keys render.
  const writing = useRef(new Set<number>());
  const [busyIds, setBusyIds] = useState<ReadonlySet<number>>(new Set());
  // Counts the starts and ends of each submission's writes, so that a read
  // can tell whether a write overlapped it.
  const writeEvents = useRef(new Map<number, number>());
  // Raised to read the shown submission's rating again.
  const [readRound, setReadRound] = useState(0);

  const countWriteEvent = (writtenId: number) =>
    writeEvents.current.set(
      writtenId,
      (writeEvents.current.get(writtenId) ?? 0) + 1,
    );

  const shownRating =
    submission && rating?.submissionId === submission.id ? rating.saved : null;

  // Sends a save or a clear for a submission, whose result `send` gives.
  const write = async (
    writtenId: number,
    send: () => Promise<StoredRating | null>,
    done: Announced,
  ): Promise<void> => {
    writing.current.add(writtenId);
    countWriteEvent(writtenId);
    setBusyIds((current) => new Set(current).add(writtenId));
    setSaveError(null);
    let saved: StoredRating | null;
    try {
      saved = await send();
    } catch (error) {
      setSaveError({ submissionId: writtenId, message: requestError(error) });
      // A read that this write overlapped is dropped, and the server may
      // hold either rating, so the shown submission's rating is read again.
      // The rating shown meanwhile stays.
      if (shownId.current === writtenId) setReadRound((round) => round + 1);
      return;
    } finally {
      writing.current.delete(writtenId);
      countWriteEvent(writtenId);
      setBusyIds((current) => {
        const updated = new Set(current);
        updated.delete(writtenId);
        return updated;
      });
    }
    setLearned((current) => new Map(current).set(writtenId, saved));
    // A rating written since a failed load replaces the missing one.
    setLoadError((current) =>
      current?.submissionId === writtenId ? null : current,
    );
    // Scoring never moves on. A judge who moved on meanwhile stays where they
    // are; on their return they see the result, or the read made then if
    // another submission's rating has taken its place.
    const shown = shownId.current === writtenId;
    setRating((current) =>
      shown || current?.submissionId === writtenId
        ? { submissionId: writtenId, saved }
        : current,
    );
    if (shown) announce(done);
  };

  const updateRating = (newRating: number) => {
    if (!submission || writing.current.has(submission.id)) return;
    const ratedId = submission.id;
    void write(
      ratedId,
      async () => {
        const { data } = await updateRatingForSubmission(ratedId, newRating);
        return { id: data.id, value: newRating };
      },
      { kind: 'score', value: newRating },
    );
  };

  // Clearing deletes the rating by its id, from the rating loaded for the
  // submission or the one a save just returned.
  const clearRating = () => {
    if (!submission || !shownRating || writing.current.has(submission.id))
      return;
    const ratingId = shownRating.id;
    void write(
      submission.id,
      async () => {
        await deleteRating(ratingId);
        return null;
      },
      { kind: 'cleared' },
    );
  };

  // Moves are announced; the photograph and its frame change with the store.
  const showNext = () => {
    nextSubmission();
    announce({ kind: 'moved' });
  };
  const showPrevious = () => {
    previousSubmission();
    announce({ kind: 'moved' });
  };
  const showSubmission = (id: number) => {
    selectSubmission(id);
    announce({ kind: 'moved' });
  };

  // Initialize the store.
  useEffect(() => {
    initialize(contestId, themeId, submissionId.current)
      .then((result) => {
        if (result === 'missing') setError(contentUnavailable());
        else setLoaded(result === 'stored');
      })
      .catch((error: unknown) => setError(requestError(error)));
  }, [contestId, themeId, initialize]);

  // The theme's ratings are requested once the theme is known to exist.
  useEffect(() => {
    if (!loaded) return;
    let active = true;
    fetchAll(() => getRatingsForTheme(parseInt(themeId, 10)))
      .then((ratings) => {
        if (!active) return;
        setThemeRatings(
          new Map(
            ratings.map((stored) => [
              stored.submission,
              { id: stored.id, value: stored.rating },
            ]),
          ),
        );
      })
      .catch(() => {
        // Nothing to show: the view leaves the count out, as it says above.
      });
    return () => {
      active = false;
    };
  }, [loaded, themeId]);

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
        if (result === 'missing') setError(contentUnavailable());
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
    // The server may have handled a read before a write for the submission
    // that is pending, or that started or finished since the read was sent.
    // The read's answer is dropped then: the write's result is the rating,
    // and a failed write reads it again.
    const writesBefore = writeEvents.current.get(currentId) ?? 0;
    const current = () =>
      active &&
      !writing.current.has(currentId) &&
      (writeEvents.current.get(currentId) ?? 0) === writesBefore;
    getRatingsForSubmission(currentId)
      .then(({ data: ratings }) => {
        if (!current()) return;
        const [found] = ratings.results;
        const saved = found ? { id: found.id, value: found.rating } : null;
        setRating({ submissionId: currentId, saved });
        setLearned((learned) => new Map(learned).set(currentId, saved));
        setLoadError(null);
      })
      .catch((error: unknown) => {
        if (!current()) return;
        setLoadError({
          submissionId: currentId,
          message: requestError(error),
        });
      });
    return () => {
      active = false;
    };
  }, [currentId, readRound]);

  useKeyPress(
    (key: string, repeat: boolean): boolean => {
      // Without a loaded theme the rater is hidden; keys must not rate it.
      if (error || !submission) return false;
      if (/^\d$/.test(key)) {
        // A held digit repeats, and each repeat would send the same score
        // again while the judge looks at the photograph. Held arrow keys
        // only step through the photographs, so they keep repeating.
        if (!repeat) updateRating(Number(key) || 10);
        return true;
      }
      if (key === 'Backspace') {
        if (!repeat) clearRating();
        return true;
      }
      if (key === 'ArrowRight') {
        if (isNext) showNext();
        return true;
      }
      if (key === 'ArrowLeft') {
        if (isPrevious) showPrevious();
        return true;
      }
      return false;
    },
    { enabled: shortcutsOn },
  );

  const toggleShortcuts = () => {
    storeShortcutsOn(!shortcutsOn);
    setShortcutsOn(!shortcutsOn);
  };

  const themeLink = `/judge/contest/${contestId}/theme/${themeId}`;

  if (error || !submission || !submissions || !contest || !theme) {
    let status: ReactNode = <LoadingProgress />;
    if (error) status = <Message severity="error">{error}</Message>;
    else if (submissions?.length === 0)
      status = <p className="body">{t('jury_no_submissions')}</p>;
    return (
      <div className="rl-on-viewing judge-view judge-view--status">
        <JudgeBar themeLink={themeLink} />
        <div className="judge-view__status">{status}</div>
      </div>
    );
  }

  const title = submission.title || t('judge_untitled');
  const position = currentIndex + 1;
  const total = submissions.length;
  const score = shownRating?.value ?? null;
  const knownRatings = themeRatings && withLearned(themeRatings, learned);
  const scored = knownRatings
    ? submissions.filter(({ id }) => knownRatings.has(id)).length
    : null;
  const frameScores = knownRatings
    ? new Map([...knownRatings].map(([id, stored]) => [id, stored.value]))
    : null;

  const announcement = (): string => {
    if (!announced) return '';
    const { event } = announced;
    if (event.kind === 'score') return t('jury_score', { score: event.value });
    if (event.kind === 'cleared') return t('judge_score_cleared');
    const place = { id: photoId(submission.id), position, total };
    if (rating?.submissionId === submission.id) {
      return rating.saved
        ? t('judge_moved_scored', { ...place, score: rating.saved.value })
        : t('judge_moved_unscored', place);
    }
    if (loadError?.submissionId === submission.id)
      return t('judge_moved', place);
    return '';
  };
  const spoken = announcement();

  const messages: ReactNode[] = [];
  if (saveError?.submissionId === submission.id)
    messages.push(
      <Message key="save" severity="error">
        {saveError.message}
      </Message>,
    );
  if (reloadError?.submissionIds.has(submission.id))
    messages.push(
      <Message key="reload" severity="error">
        {reloadError.message}
      </Message>,
    );
  if (loadError?.submissionId === submission.id)
    messages.push(
      <Message key="load" severity="error">
        {loadError.message}
      </Message>,
    );

  return (
    <div className="rl-on-viewing judge-view">
      <JudgeBar
        themeLink={themeLink}
        context={{ contest: contest.title, theme: theme.title }}
        {...(scored !== null && { progress: { scored, total } })}
      />
      <Photographs
        files={submission.files}
        title={title}
        onError={reloadSubmissions}
        onLoad={() => photographLoaded(submission.id)}
      />
      <section className="judge-label" aria-label={t('judge_photo_score')}>
        <PhotoLabel
          submissionId={submission.id}
          position={position}
          total={total}
          title={title}
          description={submission.description}
        />
        {messages.length > 0 && (
          <div className="judge-label__messages">{messages}</div>
        )}
        <span role="status" className="rl-scorepad__status">
          {spoken && <span key={announced?.count}>{spoken}</span>}
        </span>
        <div className="judge-dock">
          <ScorePad
            score={score}
            busy={busyIds.has(submission.id)}
            shortcuts={shortcutsOn}
            onScore={updateRating}
            onClear={clearRating}
          />
          <PhotoNavigation
            hasPrevious={isPrevious}
            hasNext={isNext}
            shortcuts={shortcutsOn}
            onPrevious={showPrevious}
            onNext={showNext}
          />
        </div>
        <ShortcutLegend on={shortcutsOn} onToggle={toggleShortcuts} />
      </section>
      <Filmstrip
        submissions={submissions}
        currentIndex={currentIndex}
        scores={frameScores}
        frameLink={(id) => `?submission=${id}`}
        onSelect={showSubmission}
      />
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
  ): Promise<InitializeResult> =>
    dispatch(initializeStore(contestId, themeId, submissionId)),
  reload: (contestId: string, themeId: string): Promise<InitializeResult> =>
    dispatch(reloadStore(contestId, themeId)),
  previousSubmission: () => dispatch(setPreviousSubmission()),
  nextSubmission: () => dispatch(setNextSubmission()),
  selectSubmission: (submissionId: number) =>
    dispatch(setSubmission(submissionId)),
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
