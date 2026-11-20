import { useTranslation } from 'react-i18next';
import TextField, { type InputChange } from '../../../shared/ui/TextField';
import AuthForm from './AuthForm';

export interface Fields {
  new_password: string;
  [key: string]: string;
}

export interface Errors {
  new_password: null | Array<string>;
  non_field_errors: null | Array<string>;
  [key: string]: string[] | null;
}

interface PasswordResetFormProps {
  fields: Fields;
  errors: Errors;
  onChange: (change: InputChange) => void;
  onSubmit: () => Promise<void>;
}

export default function PasswordResetForm({
  errors,
  fields,
  onChange,
  onSubmit,
}: PasswordResetFormProps) {
  const { t } = useTranslation();

  const getError = (field: string): string | null => {
    return errors[field]?.join(' ') ?? null;
  };

  return (
    <AuthForm
      submitLabel={t('password_reset')}
      error={getError('non_field_errors')}
      onSubmit={onSubmit}
    >
      <TextField
        name="new_password"
        label={t('new_password')}
        value={fields.new_password}
        error={getError('new_password')}
        type="password"
        autoComplete="new-password"
        required
        onChange={onChange}
      />
    </AuthForm>
  );
}
