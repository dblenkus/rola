import type { ReactNode } from 'react';
import usePageTitle from '../hooks/usePageTitle';
import './Page.css';

interface PageProps {
  // The page's one h1, and the document title before " · Rola".
  title: string;
  // Keeps the h1 for assistive technology only, for pages whose visible
  // heading is part of their own layout.
  titleHidden?: boolean;
  // 'standard': up to 1120 px; 'narrow': up to 400 px, for sign-in style
  // pages; 'full': the whole width inside the page margins.
  width?: 'standard' | 'narrow' | 'full';
  // Controls beside the title on wide screens and under it on phones.
  actions?: ReactNode;
  // One line under the title in body type, text-muted.
  lead?: ReactNode;
  children: ReactNode;
}

// The standard page frame: the content column with the page margins, the
// page's heading and the document title. The heading takes focus
// programmatically (tabIndex -1) when the route changes.
export default function Page({
  title,
  titleHidden,
  width = 'standard',
  actions,
  lead,
  children,
}: PageProps) {
  usePageTitle(title);
  const headEmpty = titleHidden && lead === undefined && actions === undefined;
  return (
    <div className={`ui-page ui-page--${width}`}>
      <div
        className={
          headEmpty ? 'ui-page__head ui-page__head--empty' : 'ui-page__head'
        }
      >
        <h1
          className={
            titleHidden ? 'ui-page__title visually-hidden' : 'ui-page__title'
          }
          tabIndex={-1}
        >
          {title}
        </h1>
        {lead !== undefined && <p className="ui-page__lead body">{lead}</p>}
        {actions !== undefined && (
          <div className="ui-page__actions">{actions}</div>
        )}
      </div>
      {children}
    </div>
  );
}
