import type { ReactNode } from 'react';

import './Shell.css';

// What is fixed to the bottom of the window (the notification and the update
// prompt), stacked so none covers another. The children keep their order from
// top to bottom: the last one sits nearest the corner. `theme` pins a theme
// on the stack and what it holds, whatever the page's theme.
export default function BottomStack({
  theme,
  children,
}: {
  theme?: 'light' | undefined;
  children: ReactNode;
}) {
  return (
    <div className="shell-bottom-stack" data-theme={theme}>
      {children}
    </div>
  );
}
