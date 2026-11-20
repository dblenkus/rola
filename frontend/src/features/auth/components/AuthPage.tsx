import type { ReactNode } from 'react';
import Logo from '../../../shared/ui/Logo';
import Page from '../../../shared/ui/Page';
import './AuthPage.css';

interface AuthPageProps {
  // The page's h1 and document title.
  title: string;
  children: ReactNode;
}

// The frame of the sign-in and account pages: one narrow column with the
// small logo above the page's title. The logo is decorative because the app
// bar already names Rola.
export default function AuthPage({ title, children }: AuthPageProps) {
  return (
    <Page
      width="narrow"
      title={title}
      before={
        <div className="auth-page__logo">
          <Logo variant="small" decorative />
        </div>
      }
    >
      {children}
    </Page>
  );
}
