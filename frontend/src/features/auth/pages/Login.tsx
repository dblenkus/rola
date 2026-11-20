import type { InputChange } from '../../../shared/ui/TextField';
import React from 'react';

import { withTranslation, WithTranslation } from 'react-i18next';

import { Link, Navigate, useLocation, type Location } from 'react-router';

import AuthPage from '../components/AuthPage';
import { userContext } from '../components/AuthProvider';
import LoginForm, { Errors, Fields } from '../components/LoginForm';
import { formErrors } from '../../../shared/api/errors';
import { StorageBlocked } from '../../../shared/api/token';

interface LoginViewProps extends WithTranslation {
  location: Location;
}

interface LoginViewState {
  fields: Fields;
  errors: Errors;
  redirect: boolean;
}

interface LocationState {
  from?: Location;
}

class LoginView extends React.Component<LoginViewProps, LoginViewState> {
  static contextType = userContext;
  declare context: React.ContextType<typeof userContext>;

  state = {
    fields: {
      email: '',
      password: '',
    },
    errors: {
      email: null,
      password: null,
      non_field_errors: null,
    },
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
    try {
      await this.context.login(this.state.fields);
      this.setState({ redirect: true });
    } catch (error) {
      const errors =
        error instanceof StorageBlocked
          ? { non_field_errors: [this.props.t('storage_blocked')] }
          : formErrors(error);
      this.setState({ errors: { ...this.state.errors, ...errors } });
    }
  };

  render() {
    const { errors, fields, redirect } = this.state;
    if (redirect) {
      const state: LocationState | null = this.props.location.state;
      return <Navigate to={state?.from ?? '/'} replace />;
    }

    const { t } = this.props;

    return (
      <AuthPage title={t('login')}>
        <LoginForm
          fields={fields}
          errors={errors}
          onChange={this.handleChange}
          onSubmit={this.handleSubmit}
        />
        <ul className="auth-links">
          <li>
            <Link
              className="auth-links__link body"
              to="/password-reset/request"
            >
              {t('forgot_password')}
            </Link>
          </li>
          <li>
            <Link className="auth-links__link body" to="/register">
              {t('new_registration')}
            </Link>
          </li>
        </ul>
      </AuthPage>
    );
  }
}

const RoutedView = withTranslation()(LoginView);
export default function RouteView() {
  const location = useLocation();
  return <RoutedView location={location} />;
}
