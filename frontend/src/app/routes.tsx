import { lazy, Suspense, type ComponentType } from 'react';
import { Navigate, Route, Routes } from 'react-router';

import PrivateRoute from '../features/auth/components/PrivateRoute';
import LoadingProgress from '../shared/ui/LoadingProgress';

import NotFound from './NotFound';

export const raterPath = '/judge/contest/:contestId/theme/:themeId/rate';
export const uploadPath = '/contest/:contestId/upload';

interface PageRoute {
  path: string;
  // Imports the page's module; each page is its own chunk.
  load: () => Promise<{ default: ComponentType }>;
  // Signed-in accounts only; anyone else goes to the login page and back.
  signedIn?: true;
}

// Every lazily loaded page. The routes and preloadPages both read this list,
// so no page can be routed without being preloaded.
export const pageRoutes: readonly PageRoute[] = [
  {
    path: '/contests',
    load: () => import('../features/contests/pages/ContestsList'),
  },
  {
    path: '/contest/:contestId/details',
    load: () => import('../features/contests/pages/ContestDetails'),
  },
  {
    path: uploadPath,
    load: () => import('../features/upload/pages/Upload'),
    signedIn: true,
  },
  {
    path: '/contest/:contestId/confirm',
    load: () => import('../features/upload/pages/UploadConfirm'),
    signedIn: true,
  },
  {
    path: '/user/submissions',
    load: () => import('../features/upload/pages/EditSubmissionsList'),
    signedIn: true,
  },
  { path: '/login', load: () => import('../features/auth/pages/Login') },
  {
    path: '/password-reset',
    load: () => import('../features/auth/pages/PasswordReset'),
  },
  {
    path: '/password-reset/request',
    load: () => import('../features/auth/pages/PasswordResetRequest'),
  },
  { path: '/register', load: () => import('../features/auth/pages/Register') },
  {
    path: '/register/activate',
    load: () => import('../features/auth/pages/RegisterActivate'),
  },
  {
    path: '/results',
    load: () => import('../features/results/pages/ResultsList'),
  },
  {
    path: '/results/contest/:contestId/theme/:themeId/submission/:submissionId',
    load: () => import('../features/results/pages/SubmissionResults'),
  },
  {
    path: '/results/contest/:contestId/theme/:themeId',
    load: () => import('../features/results/pages/ThemeResults'),
  },
  {
    path: '/results/contest/:contestId',
    load: () => import('../features/results/pages/SelectTheme'),
  },
  {
    path: '/judge',
    load: () => import('../features/jury/pages/SelectTheme'),
    signedIn: true,
  },
  {
    path: '/judge/contest/:contestId/theme/:themeId',
    load: () => import('../features/jury/pages/ViewTheme'),
    signedIn: true,
  },
  {
    path: raterPath,
    load: () => import('../features/jury/pages/RateSubmission'),
    signedIn: true,
  },
  {
    path: '/judge/contest/:contestId/theme/:themeId/overview',
    load: () => import('../features/jury/pages/ThemeOverview'),
    signedIn: true,
  },
  {
    path: '/admin/contest/:contestId/submissions',
    load: () => import('../features/admin/pages/SubmissionSetList'),
    signedIn: true,
  },
  {
    path: '/admin/contest/:contestId/submission/:submissionSetId',
    load: () => import('../features/admin/pages/SubmissionSetView'),
    signedIn: true,
  },
];

const routes = pageRoutes.map(({ path, load, signedIn }) => ({
  path,
  Page: lazy(load),
  signedIn: signedIn === true,
}));

// Imports every page's module, so that later navigation needs no download.
export function preloadPages(): Promise<{ default: ComponentType }[]> {
  return Promise.all(pageRoutes.map(({ load }) => load()));
}

// Each page has its own Suspense boundary, keyed by its route. Navigation
// runs in a transition, which keeps an already visible boundary's old content
// on screen, still mounted, until the next page's code arrives; a page left
// that way could still act, as the upload form does when its upload
// finishes. A new boundary shows its fallback at once instead, so the page
// that was left unmounts with the navigation.
const AppRoutes = () => {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/contests" replace />} />
      {routes.map(({ path, Page, signedIn }) => (
        <Route
          key={path}
          path={path}
          element={
            <Suspense key={path} fallback={<LoadingProgress />}>
              {signedIn ? (
                <PrivateRoute>
                  <Page />
                </PrivateRoute>
              ) : (
                <Page />
              )}
            </Suspense>
          }
        />
      ))}
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
};

export default AppRoutes;
