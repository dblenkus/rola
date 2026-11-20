import type { ReactNode } from 'react';

import Footer from '../../shared/ui/Footer';
import SkipLink from '../../shared/ui/SkipLink';

import AppBar from './AppBar';
import './Shell.css';

interface StandardLayoutProps {
  // A task screen that brings its own header and bottom bar on phones: the
  // app bar and the tab bar are hidden there. Wide screens are unchanged.
  task?: boolean;
  // The BottomStack, rendered inside the shell so it gets the shell's
  // --shell-tabbar-space.
  bottomStack: ReactNode;
  children: ReactNode;
}

// The app bar, the page and the footer.
export default function StandardLayout({
  task = false,
  bottomStack,
  children,
}: StandardLayoutProps) {
  return (
    <div className={task ? 'shell shell--task' : 'shell'}>
      <SkipLink />
      <AppBar />
      <main id="main" className="shell-main" tabIndex={-1}>
        {children}
      </main>
      {bottomStack}
      <Footer />
    </div>
  );
}
