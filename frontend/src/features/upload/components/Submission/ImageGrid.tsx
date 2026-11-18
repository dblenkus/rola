import React, { ReactNode } from 'react';

import { Grid } from '@mui/material';

interface ImageGridProps {
  children: ReactNode;
}

const ImageGrid: React.FC<ImageGridProps> = (props) => {
  const { children } = props;

  return <Grid size={{ xs: 12, sm: 6, md: 4 }}>{children}</Grid>;
};

export default ImageGrid;
