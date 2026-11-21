import headerReversedUrl from '../../design/logos/rola-logo-header-reversed.svg';
import headerUrl from '../../design/logos/rola-logo-header.svg';
import mark48Url from '../../design/logos/rola-mark-48.svg';
import smallUrl from '../../design/logos/rola-logo-small.svg';
import './Logo.css';

type LogoProps = (
  | {
      // The 57 × 26 px lockup of the app bars.
      variant: 'header';
      // The white file alone, for the `ink` and `viewing` grounds.
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
//
// The theme decides the ground, and only CSS knows the theme, so the header
// lockup without `reversed` renders both files and Logo.css shows the one
// for the ground: the ink file on a light ground, the white file on a dark
// one. Both carry the same name; the hidden one has display: none, which
// keeps it out of the accessibility tree, so a screen reader meets one
// logo in either theme (a DOM without CSS, such as jsdom's, has two).
// `small` and `mark` have no white file, so on a dark ground they are not
// shown at all.
export default function Logo({ variant, reversed, decorative }: LogoProps) {
  const alt = decorative ? '' : 'Rola';
  if (reversed) {
    return <LogoFile file={files['header-reversed']} alt={alt} />;
  }
  if (variant === 'header') {
    return (
      <>
        <LogoFile file={files.header} alt={alt} className="ui-logo--ink" />
        <LogoFile
          file={files['header-reversed']}
          alt={alt}
          className="ui-logo--reversed"
        />
      </>
    );
  }
  return <LogoFile file={files[variant]} alt={alt} className="ui-logo--ink" />;
}

function LogoFile({
  file,
  alt,
  className,
}: {
  file: (typeof files)[keyof typeof files];
  alt: string;
  className?: string;
}) {
  return (
    <img
      className={className === undefined ? 'rl-logo' : `rl-logo ${className}`}
      src={file.src}
      width={file.width}
      height={file.height}
      alt={alt}
    />
  );
}
