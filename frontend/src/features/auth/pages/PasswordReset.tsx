import type { InputChange } from '../../../shared/ui/TextField';
import React from 'react';

import { withTranslation, WithTranslation } from 'react-i18next';

import { Navigate, useLocation, type Location } from 'react-router';

import AuthPage from '../components/AuthPage';
import PasswordResetForm, {
  Errors,
  Fields,
} from '../components/PasswordResetForm';
import PasswordResetSuccess from '../components/PasswordResetSuccess';

import { formErrors } from '../../../shared/api/errors';
import { resetPassword } from '../api';

interface PasswordResetProps extends WithTranslation {
  location: Location;
}

interface PasswordResetState {
  fields: Fields;
  errors: Errors;
  done: boolean;
  redirect: boolean;
}

class PasswordResetView extends React.Component<
  PasswordResetProps,
  PasswordResetState
> {
  state = {
    fields: {
      new_password: '',
    },
    errors: {
      new_password: null,
      non_field_errors: null,
    },
    done: false,
    redirect: false,
  };

  handleChange = ({ name, value }: InputChange): void => {
    this.setState((state) => {
      const fields: Fields = Object.assign({}, state.fields);
      const errors: Errors = Object.assign({}, state.errors);
      fields[name] = value;
      errors[name] = null;
      errors.non_field_errors = null;
      return { fields, errors };
    });
  };

  handleSubmit = async (): Promise<void> => {
    const { fields } = this.state;
    const { location } = this.props;
    const token = new URLSearchParams(location.search).get('token');
    if (token) {
      try {
        await resetPassword({ ...fields, token });
        this.setState({ done: true });
      } catch (error) {
        this.setState({
          errors: { ...this.state.errors, ...formErrors(error) },
        });
      }
    } else {
      const errors: Errors = Object.assign({}, this.state.errors);
      errors.non_field_errors = [this.props.t('invalid_reset_token')];
      this.setState({ errors });
    }
  };

  handleClick = () => this.setState({ redirect: true });

  render() {
    const { done, errors, fields, redirect } = this.state;
    const { t } = this.props;

    if (redirect) {
      return <Navigate to="/login" replace />;
    }

    return (
      <AuthPage title={t('password_reset')}>
        {done ? (
          <PasswordResetSuccess onClick={this.handleClick} />
        ) : (
          <PasswordResetForm
            fields={fields}
            errors={errors}
            onChange={this.handleChange}
            onSubmit={this.handleSubmit}
          />
        )}
      </AuthPage>
    );
  }
}

const RoutedView = withTranslation()(PasswordResetView);
export default function RouteView() {
  const location = useLocation();
  return <RoutedView location={location} />;
}
