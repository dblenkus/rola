import { useEffect, useLayoutEffect, useRef, type MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

import type { JurySubmission } from '../../../shared/api/types';
import ScoreBadge from '../../../shared/ui/ScoreBadge';
import './Filmstrip.css';

// Frames shown on either side of the current one.
const reach = 20;

interface FilmstripProps {
  submissions: JurySubmission[];
  currentIndex: number;
  // The judge's score for each scored submission, or null when the judge's
  // ratings for the theme did not load; the frames then name no score.
  scores: ReadonlyMap<number, number> | null;
  // The address of a frame's photograph, for opening it elsewhere.
  frameLink: (submissionId: number) => string;
  // Shows a frame's photograph in this view.
  onSelect: (submissionId: number) => void;
}

function prefersReducedMotion(): boolean {
  return (
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

// The judge's sequence on the ink rebate: the current photograph's frame
// and up to twenty on either side, in the judge's order, each with its
// number and score.
export default function Filmstrip({
  submissions,
  currentIndex,
  scores,
  frameLink,
  onSelect,
}: FilmstripProps) {
  const { t } = useTranslation();
  const strip = useRef<HTMLElement>(null);
  const first = Math.max(currentIndex - reach, 0);
  const last = Math.min(currentIndex + reach, submissions.length - 1);
  const currentId = submissions[currentIndex]?.id;

  // Keeps the current frame in the middle of the strip. The strip scrolls by
  // itself rather than through scrollIntoView, which would also scroll the
  // page to the strip on a small screen. It starts there, and glides after a
  // move unless the judge prefers reduced motion.
  const positioned = useRef(false);
  useEffect(() => {
    const element = strip.current;
    const frame = element?.querySelector<HTMLElement>('[aria-current="true"]');
    if (!element || !frame || typeof element.scrollTo !== 'function') return;
    element.scrollTo({
      left: frame.offsetLeft - (element.clientWidth - frame.offsetWidth) / 2,
      behavior:
        positioned.current && !prefersReducedMotion() ? 'smooth' : 'instant',
    });
    positioned.current = true;
  }, [currentId]);

  // A frame that leaves the strip while it has focus would drop focus to the
  // page. React sees no blur when an element is removed, so `focused` still
  // names that frame afterwards, and focus goes to the current frame. Focus
  // moves in no other case, and without scrolling the page: the strip
  // scrolls itself to the current frame.
  const focused = useRef<number | undefined>(undefined);
  const shown = submissions.slice(first, last + 1);
  useLayoutEffect(() => {
    const id = focused.current;
    if (id === undefined || shown.some((submission) => submission.id === id))
      return;
    focused.current = undefined;
    const active = document.activeElement;
    if (active !== null && active !== document.body) return;
    strip.current
      ?.querySelector<HTMLElement>('[aria-current="true"]')
      ?.focus({ preventScroll: true });
  });

  const open = (event: MouseEvent, submissionId: number) => {
    // A click that opens a new tab or window is the browser's.
    if (
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    )
      return;
    event.preventDefault();
    if (submissionId !== currentId) onSelect(submissionId);
  };

  const name = (number: number, submissionId: number): string => {
    if (!scores) return t('judge_frame', { number });
    const score = scores.get(submissionId);
    return score === undefined
      ? t('judge_frame_unscored', { number })
      : t('judge_frame_scored', { number, score });
  };

  return (
    <nav
      ref={strip}
      className="rl-filmstrip judge-filmstrip"
      aria-label={t('judge_filmstrip', {
        first: first + 1,
        last: last + 1,
        total: submissions.length,
      })}
    >
      <ol className="rl-filmstrip__frames">
        {shown.map((submission, offset) => {
          const index = first + offset;
          const current = index === currentIndex;
          const [file] = submission.files;
          const thumbnail = file && (file.thumbnail || file.file);
          return (
            <li key={submission.id}>
              <Link
                className="rl-filmstrip__frame"
                to={frameLink(submission.id)}
                aria-label={name(index + 1, submission.id)}
                {...(current && { 'aria-current': 'true' })}
                onClick={(event) => open(event, submission.id)}
                onFocus={() => {
                  focused.current = submission.id;
                }}
                onBlur={() => {
                  focused.current = undefined;
                }}
              >
                {thumbnail ? (
                  // Signed like the main photograph; a link that expired
                  // leaves an empty frame until the view reloads the links.
                  <img
                    className="rl-filmstrip__photo"
                    src={thumbnail}
                    alt=""
                    loading="lazy"
                    decoding="async"
                  />
                ) : (
                  <span className="rl-filmstrip__photo judge-filmstrip__empty" />
                )}
                <span className="rl-filmstrip__meta">
                  <span className="rl-filmstrip__number frame-number">
                    {current && <span aria-hidden="true">▸ </span>}
                    {index + 1}
                  </span>
                  <ScoreBadge
                    score={scores?.get(submission.id) ?? null}
                    current={current}
                    decorative
                  />
                </span>
              </Link>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
