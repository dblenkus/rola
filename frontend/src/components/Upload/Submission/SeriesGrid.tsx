import React, { ReactNode } from 'react';

import { Grid } from '@mui/material';

interface SeriesGridProps {
  titleField: ReactNode;
  descriptionField: ReactNode;
}

const SeriesGrid: React.FC<SeriesGridProps> = (props) => {
  const { titleField, descriptionField } = props;

  return (
    // A full-width nested container starts the fields on their own row; the
    // fields' own margins separate them vertically.
    <Grid container size={{ xs: 12 }} columnSpacing={2}>
      <Grid size={{ xs: 12, sm: 6, md: 4 }}>{titleField}</Grid>
      <Grid size={{ xs: 12 }}>{descriptionField}</Grid>
    </Grid>
  );
};

export default SeriesGrid;
