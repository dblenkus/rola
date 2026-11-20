import type { ReactNode } from 'react';

import SkipLink from '../../shared/ui/SkipLink';

import './Shell.css';

// The page alone at the window's full width, without the app bar, the tab bar
// or the footer, for a screen that brings its own bars (the rater). With no
// tab bar, --shell-tabbar-space is 0 at every width; the BottomStack is
// rendered inside the shell so that Shell.css can lift it above the rater's
// dock where the dock is fixed to the bottom.
export default function BareLayout({
  bottomStack,
  children,
}: {
  bottomStack: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="shell shell--bare">
      <SkipLink />
      <main id="main" className="shell-main" tabIndex={-1}>
        {children}
      </main>
      {bottomStack}
    </div>
  );
}
