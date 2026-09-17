import React, { ReactNode } from 'react';

import { Card, CardContent, CardHeader, Grid } from '@material-ui/core';
import { makeStyles } from '@material-ui/core/styles';

import { uploadFormStyles } from '../../../styles/general';

export interface ThemeCardProps {
    title: string;
    children: ReactNode;
}

const useStyles = makeStyles(uploadFormStyles);

const ThemeCard: React.FC<ThemeCardProps> = (props) => {
    const classes = useStyles();
    const { title, children } = props;

    return (
        <Card className={classes.themeCard} raised>
            <CardHeader title={title} titleTypographyProps={{ align: 'center', variant: 'h3' }} />
            <CardContent>
                <Grid container alignItems="center" spacing={2}>
                    {children}
                </Grid>
            </CardContent>
        </Card>
    );
};

export default ThemeCard;
