import React, { ReactNode } from 'react';

import { Card, CardContent, CardHeader, Grid } from '@mui/material';

import { formCardSx } from '../../../../shared/ui/styles';

export interface ThemeCardProps {
  title: string;
  children: ReactNode;
}

const ThemeCard: React.FC<ThemeCardProps> = (props) => {
  const { title, children } = props;

  return (
    <Card sx={formCardSx} raised>
      <CardHeader
        title={title}
        slotProps={{
          title: { component: 'h3', align: 'center', variant: 'h3' },
        }}
      />
      <CardContent>
        <Grid container spacing={2} sx={{ alignItems: 'center' }}>
          {children}
        </Grid>
      </CardContent>
    </Card>
  );
};

export default ThemeCard;
