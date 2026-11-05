import React from 'react';

import { Typography } from '@mui/material';

const Copyright: React.FC = () => {
  return (
    <Typography
      variant="body1"
      color="textSecondary"
      align="center"
      sx={{ flexGrow: 1 }}
    >
      {new Date().getFullYear()} - <b>Domen Blenkuš</b>
    </Typography>
  );
};

export default Copyright;
