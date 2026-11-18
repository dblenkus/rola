import React, { ReactNode } from 'react';

import { Typography } from '@mui/material';

import { authSx } from '../../../shared/ui/styles';

interface RegisterConfirmProps {
  title: string;
  children: ReactNode;
}

const RegisterConfirm: React.FC<RegisterConfirmProps> = (props) => {
  const { title, children } = props;

  return (
    <>
      <Typography component="h3" variant="h6">
        {title}
      </Typography>
      <Typography sx={authSx.paragraph}>{children}</Typography>
    </>
  );
};

export default RegisterConfirm;
