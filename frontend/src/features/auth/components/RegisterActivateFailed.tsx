import React from 'react';

import { useTranslation } from 'react-i18next';

import { Typography } from '@mui/material';

import { authSx } from '../../../shared/ui/styles';

const RegisterActivateFailed: React.FC = () => {
  const { t } = useTranslation();

  return (
    <>
      <Typography component="h3" variant="h6">
        {t('activation_failed')}
      </Typography>
      <Typography sx={authSx.paragraph}>{t('invalid_token')}</Typography>
    </>
  );
};

export default RegisterActivateFailed;
