import type { InputChange } from '../../types/models';
import React from 'react';

import { useTranslation } from 'react-i18next';

import { Button } from '@mui/material';

import InputField from '../Upload/InputField';

import { authSx } from '../../shared/ui/styles';

export interface Fields {
  email: string;
  [key: string]: string;
}

interface PasswordResetRequestFormProps {
  fields: Fields;
  onChange: (event: InputChange) => void;
  onSubmit: () => Promise<void>;
}

const PasswordResetRequestForm: React.FC<PasswordResetRequestFormProps> = (
  props,
) => {
  const { t } = useTranslation();

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    props.onSubmit();
  };

  return (
    <form onSubmit={handleSubmit}>
      <InputField
        name="email"
        label={t('email')}
        value={props.fields.email}
        autoComplete="email"
        autoFocus
        required
        onChange={props.onChange}
      />
      <Button
        type="submit"
        fullWidth
        variant="contained"
        color="primary"
        sx={authSx.submit}
      >
        {t('send_reset_link')}
      </Button>
    </form>
  );
};

export default PasswordResetRequestForm;
