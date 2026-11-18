import type { InputChange } from '../../../types/models';
import React from 'react';

import { useTranslation } from 'react-i18next';

import { Alert, Button } from '@mui/material';

import InputField from '../../../components/Upload/InputField';

import { authSx } from '../../../shared/ui/styles';

export interface Fields {
  new_password: string;
  [key: string]: string;
}

export interface Errors {
  new_password: null | Array<string>;
  non_field_errors: null | Array<string>;
  [key: string]: string[] | null;
}

interface PasswordReserFormProps {
  fields: Fields;
  errors: Errors;
  onChange: (event: InputChange) => void;
  onSubmit: () => Promise<void>;
}

const PasswordResetForm: React.FC<PasswordReserFormProps> = (props) => {
  const { t } = useTranslation();
  const { errors, fields, onChange, onSubmit } = props;

  const getError = (field: string): string | null => {
    return errors[field]?.join(' ') ?? null;
  };

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    onSubmit();
  };

  return (
    <form onSubmit={handleSubmit}>
      <InputField
        name="new_password"
        label={t('new_password')}
        value={fields.new_password}
        error={getError('new_password')}
        autoComplete="new-password"
        type="password"
        required
        onChange={onChange}
      />
      {getError('non_field_errors') !== null ? (
        <Alert severity="error" sx={authSx.alert}>
          {getError('non_field_errors')}
        </Alert>
      ) : (
        false
      )}
      <Button
        type="submit"
        fullWidth
        variant="contained"
        color="primary"
        sx={authSx.submit}
      >
        {t('password_reset')}
      </Button>
    </form>
  );
};

export default PasswordResetForm;
