import { useTranslation } from 'react-i18next';
import TextField, { type InputChange } from '../../../shared/ui/TextField';
import AuthForm from './AuthForm';

export interface Fields {
  email: string;
  password: string;
  [key: string]: string;
}

export interface Errors {
  email: null | Array<string>;
  password: null | Array<string>;
  non_field_errors: null | Array<string>;
  [key: string]: string[] | null;
}

interface LoginFormProps {
  fields: Fields;
  errors: Errors;
  onChange: (change: InputChange) => void;
  onSubmit: () => Promise<void>;
}

export default function LoginForm({
  errors,
  fields,
  onChange,
  onSubmit,
}: LoginFormProps) {
  const { t } = useTranslation();

  const getError = (field: string): string | null => {
    return errors[field]?.join(' ') ?? null;
  };

  return (
    <AuthForm
      submitLabel={t('login')}
      error={getError('non_field_errors')}
      onSubmit={onSubmit}
    >
      <TextField
        name="email"
        label={t('email')}
        value={fields.email}
        error={getError('email')}
        type="email"
        autoComplete="email"
        inputMode="email"
        autoFocus
        required
        onChange={onChange}
      />
      <TextField
        name="password"
        label={t('password')}
        value={fields.password}
        error={getError('password')}
        type="password"
        autoComplete="current-password"
        required
        onChange={onChange}
      />
    </AuthForm>
  );
}
