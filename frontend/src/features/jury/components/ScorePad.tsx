import { useTranslation } from 'react-i18next';

import Button from '../../../shared/ui/Button';
import KeyCap from '../../../shared/ui/KeyCap';
import './ScorePad.css';

const scores = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

interface ScorePadProps {
  // The judge's score for the photograph on screen, or null without one.
  score: number | null;
  // While a save or a clear for the photograph is pending, no key gives a
  // score.
  busy: boolean;
  // Whether the keyboard shortcuts are on; the controls name their keys only
  // then.
  shortcuts: boolean;
  onScore: (score: number) => void;
  onClear: () => void;
}

// The keys from 1 to 10 under the chosen score and Clear. Each key is a
// toggle button and a Tab stop in a plain group, not a radio group, because
// the arrow keys move between photographs. Unavailable controls stay
// focusable with aria-disabled.
export default function ScorePad({
  score,
  busy,
  shortcuts,
  onScore,
  onClear,
}: ScorePadProps) {
  const { t } = useTranslation();
  const clearable = score !== null && !busy;
  return (
    <div className="rl-scorepad judge-scorepad">
      <div className="rl-scorepad__head judge-scorepad__head">
        <div className="rl-scorepad__actions judge-scorepad__actions">
          <div className="rl-scorepad__label small judge-scorepad__label">
            {t('judge_your_score')}
          </div>
          <Button
            variant="quiet"
            size="small"
            aria-label={t('judge_clear')}
            {...(shortcuts && { 'aria-keyshortcuts': 'Backspace' })}
            inert={!clearable}
            onPress={onClear}
          >
            {t('judge_clear')}
            <KeyCap>Backspace</KeyCap>
          </Button>
        </div>
        {/* The pressed key and the announcement carry the score. */}
        <div
          className="rl-scorepad__score judge-scorepad__score"
          aria-hidden="true"
        >
          {score === null ? (
            <span className="rl-scorepad__numeral rl-scorepad__numeral--empty">
              –
            </span>
          ) : (
            <span className="rl-scorepad__numeral score-numeral">{score}</span>
          )}
          <span className="rl-scorepad__max">/ 10</span>
        </div>
      </div>
      <div
        className="rl-scorepad__keys judge-scorepad__keys"
        role="group"
        aria-label={t('judge_score_group')}
      >
        {scores.map((value) => (
          <button
            key={value}
            type="button"
            className="rl-scorepad__key score-key"
            aria-pressed={value === score}
            {...(shortcuts && { 'aria-keyshortcuts': String(value % 10) })}
            {...(busy && { 'aria-disabled': true })}
            onClick={busy ? undefined : () => onScore(value)}
          >
            <span className="rl-scorepad__hint key-hint" aria-hidden="true">
              {value % 10}
            </span>
            {value}
          </button>
        ))}
      </div>
    </div>
  );
}
