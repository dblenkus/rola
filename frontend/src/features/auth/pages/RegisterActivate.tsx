import React from 'react';

import axios from 'axios';

import { WithTranslation, withTranslation } from 'react-i18next';

import { Navigate, useLocation, type Location } from 'react-router';

import { Alert, Card, CardContent, CardHeader, Grid } from '@mui/material';

import RegisterActivateFailed from '../components/RegisterActivateFailed';
import RegisterActivateSuccess from '../components/RegisterActivateSuccess';

import { requestError } from '../../../shared/api/errors';
import { activateUser } from '../api';

interface RegisterActivateViewProps extends WithTranslation {
  location: Location;
}

interface RegisterActivateViewState {
  succeeded: boolean | null;
  failure: string | null;
  redirect: boolean;
}

class RegisterActivateView extends React.Component<
  RegisterActivateViewProps,
  RegisterActivateViewState
> {
  state: RegisterActivateViewState = {
    succeeded: null,
    failure: null,
    redirect: false,
  };

  async componentDidMount() {
    const { location } = this.props;
    const token = new URLSearchParams(location.search).get('token');
    if (token) {
      try {
        await activateUser({ token });
        this.setState({ succeeded: true });
      } catch (error) {
        if (!axios.isAxiosError(error)) throw error;
        // Only a rejected token is invalid. A throttled or failed request
        // leaves the link usable, so it must not be reported as invalid.
        if (error.response?.status === 400) {
          this.setState({ succeeded: false });
        } else {
          this.setState({ failure: requestError(error) });
        }
      }
    } else {
      this.setState({ succeeded: false });
    }
  }

  handleClick = () => this.setState({ redirect: true });

  render() {
    const { failure, redirect, succeeded } = this.state;
    const { t } = this.props;

    if (redirect) {
      return <Navigate to="/login" replace />;
    }

    if (succeeded === null && failure === null) {
      return <></>;
    }

    return (
      <Grid container sx={{ justifyContent: 'center' }}>
        <Grid size={{ xs: 12, sm: 6, md: 4 }}>
          <Card>
            <CardHeader
              title={t('account_activation')}
              slotProps={{ title: { align: 'center' } }}
            />
            <CardContent>
              {failure ? (
                <Alert severity="error">{failure}</Alert>
              ) : succeeded ? (
                <RegisterActivateSuccess onClick={this.handleClick} />
              ) : (
                <RegisterActivateFailed />
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    );
  }
}

const RoutedView = withTranslation()(RegisterActivateView);
export default function RouteView() {
  const location = useLocation();
  return <RoutedView location={location} />;
}
