import React from 'react';

import * as Sentry from '@sentry/react';

import { BrowserRouter, Redirect, Route, Switch } from 'react-router-dom';
import { Provider } from 'react-redux';

import { CssBaseline, Container } from '@material-ui/core';

import Header from './components/Layout/Header';
import Footer from './components/Layout/Footer';
import { makeStyles } from '@material-ui/core/styles';

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

Sentry.init({ dsn: 'https://0d870d17fdb1421b8545267fc711b19a@o84586.ingest.sentry.io/5272406' });

const useStyles = makeStyles((theme) => ({
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
    const classes = useStyles();

    return (
        <div className={classes.root}>
            <Provider store={store}>
                <AuthProvider>
                    <BrowserRouter>
                        <CssBaseline />
                        <Notifications />
                        <Header />
                        <Container className={classes.container}>
                            <Switch>
                                <Route exact path="/" render={() => <Redirect to="/contests" />} />
                                <Route path="/contests" component={ContestsListView} />
                                <Route
                                    path="/contest/:contestId/details"
                                    component={ContestDetailsView}
                                />
                                <PrivateRoute
                                    path="/contest/:contestId/upload"
                                    component={UploadView}
                                />
                                <PrivateRoute
                                    path="/contest/:contestId/confirm"
                                    component={UploadConfirmView}
                                />
                                <PrivateRoute
                                    path="/user/submissions"
                                    component={EditSubmissionsList}
                                />
                                <Route path="/login" component={LoginView} />
                                <Route exact path="/password-reset" component={PasswordResetView} />
                                <Route
                                    path="/password-reset/request"
                                    component={PasswordResetRequestView}
                                />
                                <Route exact path="/register" component={RegisterView} />
                                <Route path="/register/activate" component={RegisterActivateView} />
                                <Route path="/results" component={ResultsListView} exact />

                                <Route
                                    path="/results/contest/:contestId/theme/:themeId/submission/:submissionId"
                                    component={SubmissionResultsView}
                                />
                                <Route
                                    path="/results/contest/:contestId/theme/:themeId"
                                    component={ThemeResultsView}
                                />
                                <Route
                                    path="/results/contest/:contestId"
                                    component={SelectResultsThemeView}
                                />

                                <PrivateRoute exact path="/judge" component={SelectThemeView} />
                                <PrivateRoute
                                    exact
                                    path="/judge/contest/:contestId/theme/:themeId"
                                    component={ViewThemeView}
                                />
                                <PrivateRoute
                                    path="/judge/contest/:contestId/theme/:themeId/rate"
                                    component={RateSubmissionView}
                                />
                                <PrivateRoute
                                    path="/judge/contest/:contestId/theme/:themeId/overview"
                                    component={ThemeOverview}
                                />

                                <PrivateRoute
                                    path="/admin/contest/:contestId/submissions"
                                    component={AdminSubmissionSetList}
                                />
                                <PrivateRoute
                                    path="/admin/contest/:contestId/submission/:submissionSetId"
                                    component={AdminSubmissionSetView}
                                />
                            </Switch>
                        </Container>
                        <Footer />
                    </BrowserRouter>
                </AuthProvider>
            </Provider>
        </div>
    );
};

export default App;
