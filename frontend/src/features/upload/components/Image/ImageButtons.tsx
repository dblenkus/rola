import React, { ReactNode } from 'react';

import { useTranslation } from 'react-i18next';

import { Button, Grid } from '@mui/material';

export interface ImageButtonsProps {
  handleChange: () => void;
  handleRemove: () => void;
  imageSelected: boolean;
}

interface StyledButtonProps {
  onClick: () => void;
  children: ReactNode;
}

const StyledButton: React.FC<StyledButtonProps> = (props) => {
  const { onClick, children } = props;

  return (
    <Button
      sx={{ mt: 1, p: 1 }}
      fullWidth
      variant="outlined"
      color="primary"
      onClick={onClick}
    >
      {children}
    </Button>
  );
};

const ImageButtons: React.FC<ImageButtonsProps> = (props) => {
  const { handleChange, handleRemove, imageSelected } = props;
  const { t } = useTranslation();

  const buttonWidth = imageSelected ? 6 : 12;

  return (
    <Grid container spacing={1}>
      <Grid size={{ xs: buttonWidth }}>
        <StyledButton onClick={handleChange}>
          {imageSelected ? (t('change') as string) : (t('select') as string)}
        </StyledButton>
      </Grid>
      {imageSelected && (
        <Grid size={{ xs: buttonWidth }}>
          <StyledButton onClick={handleRemove}>
            {t('remove') as string}
          </StyledButton>
        </Grid>
      )}
    </Grid>
  );
};

export default ImageButtons;
