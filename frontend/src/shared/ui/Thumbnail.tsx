import type { ReactNode } from 'react';

type ThumbnailProps = {
  // 'cover' crops the photo to fill the well; 'contain' shows it whole, for
  // portrait photos and wherever orientation matters.
  fit: 'cover' | 'contain';
  // The entrant's 64 × 64 px well instead of the 48 px tall grid cell.
  size?: 64;
  // Shown under the well in mono-caption, such as the anonymous ID "#0275".
  caption?: ReactNode;
} & (
  | {
      src: string;
      // The photo's title, or "Photo 02, portrait"; never the author.
      alt: string;
      width?: number;
      height?: number;
      // 'eager' for a thumbnail that is visible at once.
      loading?: 'lazy' | 'eager';
      label?: never;
    }
  | {
      // No photo yet: the empty well, named by this label.
      src?: never;
      label: string;
      alt?: never;
      width?: never;
      height?: never;
      loading?: never;
    }
);

// A photo shown small in a well, square-cornered and never covered. Wrap it
// in a link when it opens the photo; the link takes the focus and the name.
export default function Thumbnail(props: ThumbnailProps) {
  const { fit, size, caption } = props;
  const className = [
    'rl-thumb',
    `rl-thumb--${fit}`,
    size === 64 && 'rl-thumb--64',
  ]
    .filter(Boolean)
    .join(' ');
  const box =
    props.src === undefined ? (
      <div className="rl-thumb__box" role="img" aria-label={props.label} />
    ) : (
      <div className="rl-thumb__box">
        <img
          className="rl-thumb__img"
          src={props.src}
          alt={props.alt}
          width={props.width}
          height={props.height}
          loading={props.loading ?? 'lazy'}
          decoding="async"
        />
      </div>
    );
  if (caption === undefined) {
    return <div className={className}>{box}</div>;
  }
  return (
    <figure className={className}>
      {box}
      <figcaption className="rl-thumb__id mono-caption">{caption}</figcaption>
    </figure>
  );
}
