import React from 'react';

import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';

import { Button, Grid } from '@mui/material';
import { styled } from '@mui/material/styles';

interface UploadButtonProps {
  contestId: number;
}

const UploadLink = styled(Link)({ textDecoration: 'none' });

const UploadButton: React.FC<UploadButtonProps> = ({ contestId }) => {
  const { t } = useTranslation();
  return (
    <Grid container sx={{ justifyContent: 'center' }}>
      <UploadLink to={`/contest/${contestId}/upload`}>
        <Button
          sx={{ m: 2, py: 2, px: 4 }}
          color="primary"
          size="large"
          variant="contained"
        >
          {t('upload_photos')}
        </Button>
      </UploadLink>
    </Grid>
  );
};

export default UploadButton;
