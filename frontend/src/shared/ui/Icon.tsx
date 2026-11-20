import type { ReactNode } from 'react';

interface Glyph {
  // The side of the square the path is drawn on.
  grid: number;
  stroke: number;
  // The size the screens draw it at, in pixels.
  size: number;
  shape: ReactNode;
}

// The design system's line icons: 1.5 or 1.75 px strokes with the SVG default
// butt caps and mitre joins, copied from its iconography table.
const glyphs = {
  plus: {
    grid: 16,
    stroke: 1.75,
    size: 16,
    shape: <path d="M8 2.5v11M2.5 8h11" />,
  },
  'chevron-down': {
    grid: 16,
    stroke: 1.5,
    size: 16,
    shape: <path d="M4 6l4 4 4-4" />,
  },
  check: {
    grid: 16,
    stroke: 1.75,
    size: 16,
    shape: <path d="M3 8.5l3.25 3.25L13 5" />,
  },
  'arrow-up-right': {
    grid: 16,
    stroke: 1.5,
    size: 14,
    shape: <path d="M5 11l6-6M6 5h5v5" />,
  },
  'chevron-left': {
    grid: 24,
    stroke: 1.75,
    size: 24,
    shape: <path d="M15 5l-7 7 7 7" />,
  },
  clock: {
    grid: 16,
    stroke: 1.5,
    size: 16,
    shape: (
      <>
        <circle cx="8" cy="8" r="6.25" />
        <path d="M8 4.5V8l2.5 1.5" />
      </>
    ),
  },
  // The circle with an exclamation mark: errors, and the reason beside a
  // locked button.
  alert: {
    grid: 16,
    stroke: 1.5,
    size: 16,
    shape: (
      <>
        <circle cx="8" cy="8" r="6.25" />
        <path d="M8 4.5V9M8 11v.5" />
      </>
    ),
  },
  lock: {
    grid: 16,
    stroke: 1.5,
    size: 16,
    shape: (
      <>
        <rect x="3" y="7" width="10" height="7" rx="1" />
        <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" />
      </>
    ),
  },
  user: {
    grid: 20,
    stroke: 1.5,
    size: 20,
    shape: (
      <>
        <circle cx="10" cy="7" r="3.25" />
        <path d="M3.75 17c.75-3.25 3.25-5 6.25-5s5.5 1.75 6.25 5" />
      </>
    ),
  },
  // The award ribbon, from the AwardMark component.
  award: {
    grid: 16,
    stroke: 1.5,
    size: 16,
    shape: (
      <>
        <circle cx="8" cy="6.25" r="4.5" />
        <path d="M5.75 9.75L5 14.75l3-1.5 3 1.5-.75-5" />
      </>
    ),
  },
  // App addition, not drawn by the design system: the back chevron mirrored.
  'chevron-right': {
    grid: 24,
    stroke: 1.75,
    size: 24,
    shape: <path d="M9 5l7 7-7 7" />,
  },
  // App addition, not drawn by the design system: a cross of two 1.5 px
  // strokes on the 16 px grid.
  close: {
    grid: 16,
    stroke: 1.5,
    size: 16,
    shape: <path d="M4 4l8 8M12 4l-8 8" />,
  },
} satisfies Record<string, Glyph>;

export type IconName = keyof typeof glyphs;

interface IconProps {
  name: IconName;
  // The drawn size in pixels; the glyph's own size by default.
  size?: number;
  // Names an icon that stands alone. Without it the icon is hidden from
  // assistive technology, because words beside it carry the meaning.
  label?: string;
  className?: string;
}

// A line icon in the colour of the text around it.
export default function Icon({ name, size, label, className }: IconProps) {
  const glyph: Glyph = glyphs[name];
  const drawn = size ?? glyph.size;
  const naming =
    label === undefined
      ? { 'aria-hidden': true }
      : { role: 'img', 'aria-label': label };
  return (
    <svg
      className={className}
      width={drawn}
      height={drawn}
      viewBox={`0 0 ${glyph.grid} ${glyph.grid}`}
      focusable="false"
      {...naming}
    >
      <g fill="none" stroke="currentColor" strokeWidth={glyph.stroke}>
        {glyph.shape}
      </g>
    </svg>
  );
}
