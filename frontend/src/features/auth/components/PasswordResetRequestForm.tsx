import { useTranslation } from 'react-i18next';
import TextField, { type InputChange } from '../../../shared/ui/TextField';
import AuthForm from './AuthForm';

export interface Fields {
  email: string;
  [key: string]: string;
}

interface PasswordResetRequestFormProps {
  fields: Fields;
  onChange: (change: InputChange) => void;
  onSubmit: () => Promise<void>;
}

export default function PasswordResetRequestForm({
  fields,
  onChange,
  onSubmit,
}: PasswordResetRequestFormProps) {
  const { t } = useTranslation();

  return (
    <AuthForm submitLabel={t('send_reset_link')} onSubmit={onSubmit}>
      <TextField
        name="email"
        label={t('email')}
        value={fields.email}
        error={null}
        type="email"
        autoComplete="email"
        inputMode="email"
        autoFocus
        required
        onChange={onChange}
      />
    </AuthForm>
  );
}
