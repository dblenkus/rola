// The custom properties that the vendored rl-strip classes read.
declare module 'react' {
  interface CSSProperties {
    '--rl-value'?: string;
    '--rl-segments'?: number;
    '--rl-seg-width'?: string;
  }
}

interface ContinuousStripProps {
  value: number;
  max: number;
  // What is counted, in the interface language: "Scored 274 of 412".
  label: string;
  // Marks the bar's head with a 1 × 9 px tick.
  tick?: boolean;
  segments?: never;
  filled?: never;
  decorative?: never;
}

type SegmentedStripProps = {
  segments: number;
  filled: number;
  // A segment's width in px, or 'fill' to share the container's width.
  // The vendored default is 22 px (five stages).
  segmentWidth?: number | 'fill';
  value?: never;
  max?: never;
  tick?: never;
} & (
  | {
      // What the segments say: "Stage 3 of 5".
      label: string;
      decorative?: never;
    }
  | {
      // Words beside the strip already say the same, so it is hidden from
      // assistive technology.
      decorative: true;
      label?: never;
    }
);

type StripProps = ContinuousStripProps | SegmentedStripProps;

function requireCount(name: string, count: number): void {
  if (!Number.isInteger(count) || count < 0) {
    throw new Error(
      `Strip: ${name} must be a whole number from 0, not ${count}`,
    );
  }
}

// How far something has come: a continuous progress bar towards a total, or
// whole steps as segments. Always pair it with the figure it shows.
export default function Strip(props: StripProps) {
  if (props.segments === undefined) {
    const { value, max, label, tick } = props;
    if (!(max > 0) || !Number.isFinite(max)) {
      throw new Error(`Strip: max must be a positive number, not ${max}`);
    }
    if (!(value >= 0 && value <= max)) {
      throw new Error(
        `Strip: value must be between 0 and ${max}, not ${value}`,
      );
    }
    return (
      <div
        className="rl-strip"
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={value}
        style={{ '--rl-value': `${(value / max) * 100}%` }}
      >
        <span className="rl-strip__bar" />
        {tick && <span className="rl-strip__tick" />}
      </div>
    );
  }

  const { segments, filled, segmentWidth } = props;
  requireCount('segments', segments);
  requireCount('filled', filled);
  if (segments === 0) {
    throw new Error('Strip: segments must be at least 1');
  }
  if (filled > segments) {
    throw new Error(`Strip: filled (${filled}) exceeds segments (${segments})`);
  }
  const semantics = props.decorative
    ? { 'aria-hidden': true }
    : { role: 'img', 'aria-label': props.label };
  return (
    <div
      className="rl-strip rl-strip--segmented"
      {...semantics}
      style={{
        '--rl-segments': segments,
        ...(segmentWidth !== undefined && {
          '--rl-seg-width':
            segmentWidth === 'fill' ? '1fr' : `${segmentWidth}px`,
        }),
      }}
    >
      {Array.from({ length: segments }, (_, index) => (
        <span
          key={index}
          className={
            index < filled ? 'rl-strip__seg rl-strip__seg--on' : 'rl-strip__seg'
          }
        />
      ))}
    </div>
  );
}
