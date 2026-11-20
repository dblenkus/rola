import type { FormEvent, ReactNode } from 'react';
import Button from '../../../shared/ui/Button';
import Message from '../../../shared/ui/Message';
import './AuthPage.css';

interface AuthFormProps {
  // The label of the form's one primary button.
  submitLabel: string;
  // The error that belongs to no field, or null.
  error?: string | null;
  onSubmit: () => void;
  // The fields.
  children: ReactNode;
}

// An account form: its fields, the error that belongs to no field and the
// full-width submit button. The browser checks required fields and field
// types before onSubmit is called.
export default function AuthForm({
  submitLabel,
  error = null,
  onSubmit,
  children,
}: AuthFormProps) {
  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    onSubmit();
  };

  return (
    <form className="auth-form" onSubmit={handleSubmit}>
      {children}
      {error !== null && <Message severity="error">{error}</Message>}
      <div className="auth-form__submit">
        <Button type="submit" variant="primary" block>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
