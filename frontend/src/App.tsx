import { BrowserRouter, Navigate, Route, Routes } from 'react-router';
import { Provider } from 'react-redux';

import { CssBaseline, Container } from '@mui/material';

import Header from './components/Layout/Header';
import Footer from './components/Layout/Footer';
import { makeStyles } from 'tss-react/mui';

import ContestsListView from './views/ContestsList';
import ContestDetailsView from './views/ContestDetails';
import LoginView from './views/Login';
import RegisterView from './views/Register';
import RegisterActivateView from './views/RegisterActivate';
import ResultsListView from './views/ResultsList';
import UploadView from './views/Upload';
import UploadConfirmView from './views/UploadConfirm';
import EditSubmissionsList from './views/EditSubmissionsList';
import PasswordResetRequestView from './views/PasswordResetRequest';
import PasswordResetView from './views/PasswordReset';
import SelectThemeView from './views/judge/SelectTheme';
import ViewThemeView from './views/judge/ViewTheme';
import RateSubmissionView from './views/judge/RateSubmission';
import AdminSubmissionSetList from './views/admin/SubmissionSetList';
import AdminSubmissionSetView from './views/admin/SubmissionSetView';

import AuthProvider from './components/Auth/AuthProvider';
import Notifications from './components/Notifications/Notifications';
import PrivateRoute from './components/Auth/PrivateRoute';

import store from './store';
import ThemeOverview from './views/judge/ThemeOverview';
import ThemeResultsView from './views/results/ThemeResults';
import SelectResultsThemeView from './views/results/SelectTheme';
import SubmissionResultsView from './views/results/SubmissionResults';

const useStyles = makeStyles()((theme) => ({
  container: {
    marginTop: theme.spacing(2),
    marginBottom: theme.spacing(4),
  },
  root: {
    display: 'flex',
    flexDirection: 'column',
    minHeight: '100vh',
  },
}));

const App = () => {
  const { classes } = useStyles();

  return (
    <div className={classes.root}>
      <Provider store={store}>
        <AuthProvider>
          <BrowserRouter>
            <CssBaseline />
            <Notifications />
            <Header />
            <Container className={classes.container}>
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
                  path="/judge/contest/:contestId/theme/:themeId/rate"
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
            </Container>
            <Footer />
          </BrowserRouter>
        </AuthProvider>
      </Provider>
    </div>
  );
};

export default App;
