import headerReversedUrl from '../../design/logos/rola-logo-header-reversed.svg';
import headerUrl from '../../design/logos/rola-logo-header.svg';
import mark48Url from '../../design/logos/rola-mark-48.svg';
import smallUrl from '../../design/logos/rola-logo-small.svg';

type LogoProps = (
  | {
      // The 57 × 26 px lockup of the app bars.
      variant: 'header';
      // The white file, for the `ink` and `viewing` grounds.
      reversed?: boolean;
    }
  | {
      // `small`: the lockup at 40 px tall (sign-in pages); `mark`: the R
      // alone at 48 px (the loading state). Neither has a reversed file.
      variant: 'small' | 'mark';
      reversed?: never;
    }
) & {
  // Leaves the image unnamed because a parent, such as a link, names it.
  decorative?: boolean;
};

const files = {
  header: { src: headerUrl, width: 57, height: 26 },
  'header-reversed': { src: headerReversedUrl, width: 57, height: 26 },
  // The viewBox is 158.25 × 72.39; the image keeps its aspect ratio inside
  // the box, as the design system's own sign-in markup does.
  small: { src: smallUrl, width: 87, height: 40 },
  mark: { src: mark48Url, width: 48, height: 48 },
} as const;

// The Rola logo as one of the supplied files, at the one size it is drawn
// for. The artwork is never inlined, recoloured or scaled.
export default function Logo({ variant, reversed, decorative }: LogoProps) {
  const file = files[reversed ? 'header-reversed' : variant];
  return (
    <img
      className="rl-logo"
      src={file.src}
      width={file.width}
      height={file.height}
      alt={decorative ? '' : 'Rola'}
    />
  );
}
