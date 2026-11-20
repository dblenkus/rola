type ScoreBadgeProps = {
  // A whole score from 1 to 10, or null when the photo is not scored yet.
  score: number | null;
  // Marks the photo on screen with more weight.
  current?: boolean;
  // The 32 px badge instead of the filmstrip's 20 px one.
  size?: 'lg';
} & (
  | {
      // The badge's name in the interface language: "Score 8" or "Unscored".
      label: string;
      decorative?: never;
    }
  | {
      // A parent, such as a filmstrip frame's link, names the score.
      decorative: true;
      label?: never;
    }
);

// A judge's score for one photo: inverted when scored, an outlined dash when
// not. Its default colours are for the `ink` ground; inside rl-on-viewing it
// takes the viewing surface's colours.
export default function ScoreBadge(props: ScoreBadgeProps) {
  const { score, current, size } = props;
  if (
    score !== null &&
    !(Number.isInteger(score) && score >= 1 && score <= 10)
  ) {
    throw new Error(
      `ScoreBadge: score must be a whole number from 1 to 10, not ${score}`,
    );
  }
  const className = [
    'rl-score-badge',
    score === null ? 'rl-score-badge--unscored' : 'rl-score-badge--scored',
    current && 'rl-score-badge--current',
    size === 'lg' && 'rl-score-badge--lg',
  ]
    .filter(Boolean)
    .join(' ');
  const semantics = props.decorative
    ? { 'aria-hidden': true }
    : { role: 'img', 'aria-label': props.label };
  return (
    <span className={className} {...semantics}>
      {score === null ? '–' : score}
    </span>
  );
}
