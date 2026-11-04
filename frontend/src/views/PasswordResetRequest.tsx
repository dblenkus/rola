import type { InputChange } from '../types/models';
import React from 'react';

import { withTranslation, WithTranslation } from 'react-i18next';

import { Alert, Card, CardContent, CardHeader, Grid } from '@mui/material';

import PasswordResetRequestForm, {
  Fields,
} from '../components/Auth/PasswordResetRequestForm';
import PasswordResetRequestConfirm from '../components/Auth/PasswordResetRequestConfirm';

import UserService from '../services/UserService';
import { requestError } from '../services/errors';

type PasswordResetRequestViewProps = WithTranslation;

interface PasswordResetRequestViewState {
  error: string | null;
  done: boolean;
  fields: Fields;
}

class PasswordResetRequestView extends React.Component<
  PasswordResetRequestViewProps,
  PasswordResetRequestViewState
> {
  state: PasswordResetRequestViewState = {
    error: null,
    done: false,
    fields: {
      email: '',
    },
  };

  handleChange = ({ name, value }: InputChange): void => {
    this.setState((state) => {
      const fields: Fields = Object.assign({}, state.fields);
      fields[name] = value;
      return { fields };
    });
  };

  handleSubmit = async (): Promise<void> => {
    const { fields } = this.state;
    this.setState({ error: null });
    try {
      await UserService.requestPasswordReset(fields);
      this.setState({ done: true });
    } catch (error) {
      this.setState({ error: requestError(error) });
    }
  };

  render() {
    const { done, error, fields } = this.state;
    const { t } = this.props;

    return (
      <Grid container sx={{ justifyContent: 'center' }}>
        <Grid size={{ xs: 12, sm: 6, md: 4 }}>
          <Card>
            <CardHeader
              title={t('password_reset')}
              slotProps={{ title: { align: 'center' } }}
            />
            <CardContent>
              {error && <Alert severity="error">{error}</Alert>}
              {done ? (
                <PasswordResetRequestConfirm email={fields.email} />
              ) : (
                <PasswordResetRequestForm
                  fields={fields}
                  onChange={this.handleChange}
                  onSubmit={this.handleSubmit}
                />
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    );
  }
}

export default withTranslation()(PasswordResetRequestView);
