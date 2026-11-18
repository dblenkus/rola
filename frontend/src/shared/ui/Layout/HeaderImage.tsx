import React from 'react';

import { Box } from '@mui/material';

interface HeaderImageProps {
  src: string;
}

const HeaderImage: React.FC<HeaderImageProps> = ({ src }) => {
  return (
    <Box component="img" src={src} alt="Header" sx={{ maxWidth: '100%' }} />
  );
};

export default HeaderImage;
