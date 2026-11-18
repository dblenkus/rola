import React from 'react';
import { BrowserRouter, Navigate, Route, Routes, useMatch } from 'react-router';
import { Provider } from 'react-redux';

import { Box, CssBaseline, Container } from '@mui/material';

import Header from '../shared/ui/Layout/Header';
import Footer from '../shared/ui/Layout/Footer';

import ContestsListView from '../views/ContestsList';
import ContestDetailsView from '../views/ContestDetails';
import LoginView from '../views/Login';
import RegisterView from '../views/Register';
import RegisterActivateView from '../views/RegisterActivate';
import ResultsListView from '../views/ResultsList';
import UploadView from '../views/Upload';
import UploadConfirmView from '../views/UploadConfirm';
import EditSubmissionsList from '../views/EditSubmissionsList';
import PasswordResetRequestView from '../views/PasswordResetRequest';
import PasswordResetView from '../views/PasswordReset';
import SelectThemeView from '../views/judge/SelectTheme';
import ViewThemeView from '../views/judge/ViewTheme';
import RateSubmissionView from '../views/judge/RateSubmission';
import AdminSubmissionSetList from '../views/admin/SubmissionSetList';
import AdminSubmissionSetView from '../views/admin/SubmissionSetView';

import AuthProvider from '../components/Auth/AuthProvider';
import Notifications from '../components/Notifications/Notifications';
import PrivateRoute from '../components/Auth/PrivateRoute';

import store from './store';
import ThemeOverview from '../views/judge/ThemeOverview';
import ThemeResultsView from '../views/results/ThemeResults';
import SelectResultsThemeView from '../views/results/SelectTheme';
import SubmissionResultsView from '../views/results/SubmissionResults';

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
