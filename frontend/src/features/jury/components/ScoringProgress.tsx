import Strip from '../../../shared/ui/Strip';
import './ScoringProgress.css';

interface ScoringProgressProps {
  scored: number;
  total: number;
  // The strip's accessible name: "Scored 12 of 40".
  label: string;
  // A word before the figure, such as "Scored".
  caption?: string;
}

// How many photographs the judge has scored, as "12 / 40" over a continuous
// strip. A theme without photographs shows "0 / 0" and no strip, which has
// no share to draw. A count above the total, which the figures should never
// give, is shown as it is, without a strip that could not draw it.
export default function ScoringProgress({
  scored,
  total,
  label,
  caption,
}: ScoringProgressProps) {
  return (
    <div className="jury-progress">
      <p className="jury-progress__figure body-dense">
        {caption !== undefined && (
          <span className="jury-progress__caption">{caption} </span>
        )}
        <span className="jury-progress__count">
          {scored} / {total}
        </span>
      </p>
      {total > 0 && scored <= total && (
        <Strip value={scored} max={total} label={label} />
      )}
    </div>
  );
}
