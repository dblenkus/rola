import React from 'react';

import { Button, Typography } from '@mui/material';

import { authSx } from '../../../../shared/ui/styles';

interface RegisterActivateSuccessProps {
  title: string;
  buttonText: string;
  onClick: () => void;
}

const RegisterActivateSuccess: React.FC<RegisterActivateSuccessProps> = (
  props,
) => {
  const { buttonText, title, onClick } = props;

  return (
    <>
      <Typography component="h3" variant="h6">
        {title}
      </Typography>
      <Button
        type="submit"
        fullWidth
        variant="contained"
        color="primary"
        sx={authSx.submit}
        onClick={() => onClick()}
      >
        {buttonText}
      </Button>
    </>
  );
};

export default RegisterActivateSuccess;
