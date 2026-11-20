import type { ReactNode } from 'react';

// The judge's keyboard legend: KeyCaps and the words for their actions in
// one wrapping line of plain text, in the order of the controls above it.
export default function KeyLegend({ children }: { children: ReactNode }) {
  return <div className="rl-keylegend small">{children}</div>;
}

// The "·" between two groups of keys. Assistive technology skips it; the
// words around it carry the meaning.
export function KeyLegendSeparator() {
  return (
    <span className="rl-keylegend__sep" aria-hidden="true">
      ·
    </span>
  );
}

// Starts the legend's next line, such as the navigation keys after the
// score keys.
export function KeyLegendBreak() {
  return <span className="rl-keylegend__break" />;
}
