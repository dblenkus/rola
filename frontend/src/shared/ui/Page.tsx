import type { ReactNode } from 'react';
import usePageTitle from '../hooks/usePageTitle';
import './Page.css';

interface PageProps {
  // The page's one h1, and the document title before " · Rola".
  title: string;
  // Keeps the h1 for assistive technology only, for pages whose visible
  // heading is part of their own layout.
  titleHidden?: boolean;
  // The page renders its one h1 itself, inside its own layout; `title` still
  // sets the document title.
  ownHeading?: boolean;
  // 'standard': up to 1120 px; 'narrow': up to 400 px, for sign-in style
  // pages; 'full': the whole width inside the page margins.
  width?: 'standard' | 'narrow' | 'full';
  // Content above the title, in the page column, such as the sign-in
  // pages' logo. It brings its own space to the title.
  before?: ReactNode;
  // Controls beside the title on wide screens and under it on phones.
  actions?: ReactNode;
  // One line under the title, text-muted.
  lead?: ReactNode;
  // The lead's type: `body`, or `small` for a meta line such as a deadline.
  leadSize?: 'body' | 'small';
  children: ReactNode;
}

// The standard page frame: the content column with the page margins, the
// page's heading and the document title. After a navigation the shell moves
// focus to <main>, not to this heading.
export default function Page({
  title,
  titleHidden,
  ownHeading,
  width = 'standard',
  before,
  actions,
  lead,
  leadSize = 'body',
  children,
}: PageProps) {
  usePageTitle(title);
  const extras =
    before !== undefined || lead !== undefined || actions !== undefined;
  const headEmpty = titleHidden && !extras;
  return (
    <div className={`ui-page ui-page--${width}`}>
      {(!ownHeading || extras) && (
        <div
          className={
            headEmpty ? 'ui-page__head ui-page__head--empty' : 'ui-page__head'
          }
        >
          {before !== undefined && (
            <div className="ui-page__before">{before}</div>
          )}
          {!ownHeading && (
            <h1
              className={
                titleHidden
                  ? 'ui-page__title visually-hidden'
                  : 'ui-page__title'
              }
            >
              {title}
            </h1>
          )}
          {lead !== undefined && (
            <p className={`ui-page__lead ${leadSize}`}>{lead}</p>
          )}
          {actions !== undefined && (
            <div className="ui-page__actions">{actions}</div>
          )}
        </div>
      )}
      {children}
    </div>
  );
}
