import type { ReactNode } from 'react';

import './Shell.css';

// What is fixed to the bottom of the window (the notification and the update
// prompt), stacked so none covers another. The children keep their order from
// top to bottom: the last one sits nearest the corner.
export default function BottomStack({ children }: { children: ReactNode }) {
  return <div className="shell-bottom-stack">{children}</div>;
}
