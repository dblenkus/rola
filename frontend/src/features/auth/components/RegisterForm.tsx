import { useTranslation } from 'react-i18next';
import TextField, { type InputChange } from '../../../shared/ui/TextField';
import AuthForm from './AuthForm';

export interface Fields {
  first_name: string;
  last_name: string;
  email: string;
  password: string;
  address: string;
  city: string;
  postal_code: string;
  country: string;
  [key: string]: string;
}

export interface Errors {
  first_name: null | Array<string>;
  last_name: null | Array<string>;
  email: null | Array<string>;
  password: null | Array<string>;
  address: null | Array<string>;
  city: null | Array<string>;
  postal_code: null | Array<string>;
  country: null | Array<string>;
  non_field_errors: null | Array<string>;
  [key: string]: string[] | null;
}

interface RegisterFormProps {
  fields: Fields;
  errors: Errors;
  onChange: (change: InputChange) => void;
  onSubmit: () => Promise<void>;
}

export default function RegisterForm({
  errors,
  fields,
  onChange,
  onSubmit,
}: RegisterFormProps) {
  const { t } = useTranslation();

  const getError = (field: string): string | null => {
    return errors[field]?.join(' ') ?? null;
  };

  return (
    <AuthForm
      submitLabel={t('register')}
      error={getError('non_field_errors')}
      onSubmit={onSubmit}
    >
      <div className="auth-form__pair">
        <TextField
          name="first_name"
          label={t('first_name')}
          value={fields.first_name}
          error={getError('first_name')}
          autoComplete="given-name"
          autoFocus
          required
          onChange={onChange}
        />
        <TextField
          name="last_name"
          label={t('last_name')}
          value={fields.last_name}
          error={getError('last_name')}
          autoComplete="family-name"
          required
          onChange={onChange}
        />
      </div>
      <TextField
        name="email"
        label={t('email')}
        value={fields.email}
        error={getError('email')}
        type="email"
        autoComplete="email"
        inputMode="email"
        required
        onChange={onChange}
      />
      <TextField
        name="password"
        label={t('password')}
        value={fields.password}
        error={getError('password')}
        type="password"
        autoComplete="new-password"
        required
        onChange={onChange}
      />
      <TextField
        name="address"
        label={t('address')}
        value={fields.address}
        error={getError('address')}
        autoComplete="street-address"
        required
        onChange={onChange}
      />
      <TextField
        name="city"
        label={t('city')}
        value={fields.city}
        error={getError('city')}
        autoComplete="address-level2"
        required
        onChange={onChange}
      />
      {/* Foreign postal codes have letters, so the keyboard stays a text
          one. */}
      <TextField
        name="postal_code"
        label={t('postal_code')}
        value={fields.postal_code}
        error={getError('postal_code')}
        autoComplete="postal-code"
        inputMode="text"
        required
        onChange={onChange}
      />
      <TextField
        name="country"
        label={t('country')}
        value={fields.country}
        error={getError('country')}
        autoComplete="country-name"
        required
        onChange={onChange}
      />
    </AuthForm>
  );
}
