import type { InputChange } from '../../../shared/ui/TextField';
import React from 'react';

import { withTranslation, WithTranslation } from 'react-i18next';

import Message from '../../../shared/ui/Message';
import AuthPage from '../components/AuthPage';
import PasswordResetRequestForm, {
  Fields,
} from '../components/PasswordResetRequestForm';
import PasswordResetRequestConfirm from '../components/PasswordResetRequestConfirm';

import { requestError } from '../../../shared/api/errors';
import { requestPasswordReset } from '../api';

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
      await requestPasswordReset(fields);
      this.setState({ done: true });
    } catch (error) {
      this.setState({ error: requestError(error) });
    }
  };

  render() {
    const { done, error, fields } = this.state;
    const { t } = this.props;

    return (
      <AuthPage title={t('password_reset')}>
        {error && (
          <div className="auth-page__message">
            <Message severity="error">{error}</Message>
          </div>
        )}
        {done ? (
          <PasswordResetRequestConfirm email={fields.email} />
        ) : (
          <PasswordResetRequestForm
            fields={fields}
            onChange={this.handleChange}
            onSubmit={this.handleSubmit}
          />
        )}
      </AuthPage>
    );
  }
}

export default withTranslation()(PasswordResetRequestView);
