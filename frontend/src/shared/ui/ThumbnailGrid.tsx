import type { ReactNode } from 'react';
import './ThumbnailGrid.css';

interface ThumbnailGridProps {
  children: ReactNode;
  // 'page' fits as many columns as the page is wide, with 3:2 cells;
  // 'panel' is the design system's six columns of 48 px tall cells, for a
  // narrow side panel.
  layout?: 'page' | 'panel';
}

// A grid of Thumbnails, 8 px apart.
export default function ThumbnailGrid({
  children,
  layout = 'page',
}: ThumbnailGridProps) {
  return (
    <div
      className={
        layout === 'page'
          ? 'rl-thumb-grid ui-thumb-grid--page'
          : 'rl-thumb-grid'
      }
    >
      {children}
    </div>
  );
}
