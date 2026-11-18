import React from 'react';
import { BrowserRouter, Navigate, Route, Routes, useMatch } from 'react-router';
import { Provider } from 'react-redux';

import { Box, CssBaseline, Container } from '@mui/material';

import Header from '../shared/ui/Layout/Header';
import Footer from '../shared/ui/Layout/Footer';

import ContestsListView from '../features/contests/pages/ContestsList';
import ContestDetailsView from '../features/contests/pages/ContestDetails';
import LoginView from '../features/auth/pages/Login';
import RegisterView from '../features/auth/pages/Register';
import RegisterActivateView from '../features/auth/pages/RegisterActivate';
import ResultsListView from '../features/results/pages/ResultsList';
import UploadView from '../features/upload/pages/Upload';
import UploadConfirmView from '../features/upload/pages/UploadConfirm';
import EditSubmissionsList from '../features/upload/pages/EditSubmissionsList';
import PasswordResetRequestView from '../features/auth/pages/PasswordResetRequest';
import PasswordResetView from '../features/auth/pages/PasswordReset';
import SelectThemeView from '../features/jury/pages/SelectTheme';
import ViewThemeView from '../features/jury/pages/ViewTheme';
import RateSubmissionView from '../features/jury/pages/RateSubmission';
import AdminSubmissionSetList from '../views/admin/SubmissionSetList';
import AdminSubmissionSetView from '../views/admin/SubmissionSetView';

import AuthProvider from '../features/auth/components/AuthProvider';
import Notifications from '../features/notifications/components/Notifications';
import PrivateRoute from '../features/auth/components/PrivateRoute';

import store from './store';
import ThemeOverview from '../features/jury/pages/ThemeOverview';
import ThemeResultsView from '../features/results/pages/ThemeResults';
import SelectResultsThemeView from '../features/results/pages/SelectTheme';
import SubmissionResultsView from '../features/results/pages/SubmissionResults';

const raterPath = '/judge/contest/:contestId/theme/:themeId/rate';

// The rater gives a series of photographs the window's full width. It stays
// in the page's flow, so the footer follows it.
const Main: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const rater = useMatch(raterPath);
  return (
    <Container maxWidth={rater ? false : 'lg'} sx={{ mt: 2, mb: 4 }}>
      {children}
    </Container>
  );
};

const App = () => {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <Provider store={store}>
        <AuthProvider>
          <BrowserRouter>
            <CssBaseline />
            <Notifications />
            <Header />
            <Main>
              <Routes>
                <Route path="/" element={<Navigate to="/contests" replace />} />
                <Route path="/contests" element={<ContestsListView />} />
                <Route
                  path="/contest/:contestId/details"
                  element={<ContestDetailsView />}
                />
                <Route
                  path="/contest/:contestId/upload"
                  element={
                    <PrivateRoute>
                      <UploadView />
                    </PrivateRoute>
                  }
                />
                <Route
                  path="/contest/:contestId/confirm"
                  element={
                    <PrivateRoute>
                      <UploadConfirmView />
                    </PrivateRoute>
                  }
                />
                <Route
                  path="/user/submissions"
                  element={
                    <PrivateRoute>
                      <EditSubmissionsList />
                    </PrivateRoute>
                  }
                />
                <Route path="/login" element={<LoginView />} />
                <Route path="/password-reset" element={<PasswordResetView />} />
                <Route
                  path="/password-reset/request"
                  element={<PasswordResetRequestView />}
                />
                <Route path="/register" element={<RegisterView />} />
                <Route
                  path="/register/activate"
                  element={<RegisterActivateView />}
                />
                <Route path="/results" element={<ResultsListView />} />

                <Route
                  path="/results/contest/:contestId/theme/:themeId/submission/:submissionId"
                  element={<SubmissionResultsView />}
                />
                <Route
                  path="/results/contest/:contestId/theme/:themeId"
                  element={<ThemeResultsView />}
                />
                <Route
                  path="/results/contest/:contestId"
                  element={<SelectResultsThemeView />}
                />

                <Route
                  path="/judge"
                  element={
                    <PrivateRoute>
                      <SelectThemeView />
                    </PrivateRoute>
                  }
                />
                <Route
                  path="/judge/contest/:contestId/theme/:themeId"
                  element={
                    <PrivateRoute>
                      <ViewThemeView />
                    </PrivateRoute>
                  }
                />
                <Route
                  path={raterPath}
                  element={
                    <PrivateRoute>
                      <RateSubmissionView />
                    </PrivateRoute>
                  }
                />
                <Route
                  path="/judge/contest/:contestId/theme/:themeId/overview"
                  element={
                    <PrivateRoute>
                      <ThemeOverview />
                    </PrivateRoute>
                  }
                />

                <Route
                  path="/admin/contest/:contestId/submissions"
                  element={
                    <PrivateRoute>
                      <AdminSubmissionSetList />
                    </PrivateRoute>
                  }
                />
                <Route
                  path="/admin/contest/:contestId/submission/:submissionSetId"
                  element={
                    <PrivateRoute>
                      <AdminSubmissionSetView />
                    </PrivateRoute>
                  }
                />
              </Routes>
            </Main>
            <Footer />
          </BrowserRouter>
        </AuthProvider>
      </Provider>
    </Box>
  );
};

export default App;
