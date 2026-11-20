import type { ReactNode } from 'react';

import SkipLink from '../../shared/ui/SkipLink';

import './Shell.css';

// The page alone at the window's full width, without the app bar, the tab bar
// or the footer, for a screen that brings its own bar (the rater).
export default function BareLayout({ children }: { children: ReactNode }) {
  return (
    <div className="shell shell--bare">
      <SkipLink />
      <main id="main" className="shell-main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
