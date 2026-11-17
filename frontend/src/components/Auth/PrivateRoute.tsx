import { Fragment, useContext, type ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router';
import { userContext } from './AuthProvider';

export default function PrivateRoute({ children }: { children: ReactNode }) {
  const user = useContext(userContext);
  const location = useLocation();
  return user.isLoggedIn() ? (
    // Another account signing in, from another tab too, opens the page
    // afresh, so nothing loaded for the previous account stays on screen.
    <Fragment key={user.user?.email}>{children}</Fragment>
  ) : (
    <Navigate to="/login" state={{ from: location }} replace />
  );
}
