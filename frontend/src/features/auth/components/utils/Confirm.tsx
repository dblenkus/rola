import type { ReactNode } from 'react';
import '../AuthPage.css';

interface ConfirmProps {
  title: string;
  // One or two lines of body text.
  children: ReactNode;
}

// A screen that says what happened and what to do next outside Rola, such as
// following the link in an email.
export default function Confirm({ title, children }: ConfirmProps) {
  return (
    <div className="auth-status">
      <h2 className="auth-status__title h3">{title}</h2>
      <p className="auth-status__text body">{children}</p>
    </div>
  );
}
