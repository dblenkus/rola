import React from 'react';

import { Link } from 'react-router';

import { Button, Grid } from '@mui/material';
import { styled } from '@mui/material/styles';

interface UploadButtonProps {
  contestId: number;
}

const UploadLink = styled(Link)({ textDecoration: 'none' });

const UploadButton: React.FC<UploadButtonProps> = ({ contestId }) => {
  return (
    <Grid container sx={{ justifyContent: 'center' }}>
      <UploadLink to={`/contest/${contestId}/upload`}>
        <Button
          sx={{ m: 2, py: 2, px: 4 }}
          color="primary"
          size="large"
          variant="contained"
        >
          Upload Photos
        </Button>
      </UploadLink>
    </Grid>
  );
};

export default UploadButton;
