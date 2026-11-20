import type { InputChange } from '../../../shared/ui/TextField';
import React from 'react';

import { withTranslation, WithTranslation } from 'react-i18next';

import { Link } from 'react-router';

import AuthPage from '../components/AuthPage';
import RegisterForm, { Errors, Fields } from '../components/RegisterForm';
import RegisterConfirm from '../components/RegisterConfirm';

import { formErrors } from '../../../shared/api/errors';
import { registerUser } from '../api';

type RegisterViewProps = WithTranslation;

interface RegisterViewState {
  fields: Fields;
  errors: Errors;
  done: boolean;
}

class RegisterView extends React.Component<
  RegisterViewProps,
  RegisterViewState
> {
  state = {
    fields: {
      first_name: '',
      last_name: '',
      email: '',
      password: '',
      address: '',
      city: '',
      postal_code: '',
      country: '',
    },
    errors: {
      first_name: null,
      last_name: null,
      email: null,
      password: null,
      address: null,
      city: null,
      postal_code: null,
      country: null,
      non_field_errors: null,
    },
    done: false,
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
    try {
      await registerUser(fields);
      this.setState({ done: true });
    } catch (error) {
      this.setState({ errors: { ...this.state.errors, ...formErrors(error) } });
    }
  };

  render() {
    const { errors, done, fields } = this.state;
    const { t } = this.props;

    return (
      <AuthPage title={t('register')}>
        {done ? (
          <RegisterConfirm email={fields.email} />
        ) : (
          <>
            <RegisterForm
              fields={fields}
              errors={errors}
              onChange={this.handleChange}
              onSubmit={this.handleSubmit}
            />
            <ul className="auth-links">
              <li>
                <Link className="auth-links__link body" to="/login">
                  {t('already_have_account')}
                </Link>
              </li>
            </ul>
          </>
        )}
      </AuthPage>
    );
  }
}

export default withTranslation()(RegisterView);
