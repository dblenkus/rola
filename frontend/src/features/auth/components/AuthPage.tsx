import type { ReactNode } from 'react';
import Page from '../../../shared/ui/Page';
import './AuthPage.css';

interface AuthPageProps {
  // The page's h1 and document title.
  title: string;
  children: ReactNode;
}

// The frame of the sign-in and account pages: one narrow column. The app
// bar above it carries the logo.
export default function AuthPage({ title, children }: AuthPageProps) {
  return (
    <Page width="narrow" title={title}>
      {children}
    </Page>
  );
}
