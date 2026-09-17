import React, { ReactChild } from 'react';

import { Grid } from '@material-ui/core';
import { makeStyles } from '@material-ui/core/styles';

import { uploadFormStyles } from '../../../styles/general';

interface ImageGridProps {
    children: ReactChild;
}

const useStyles = makeStyles(uploadFormStyles);

const ImageGrid: React.FC<ImageGridProps> = (props) => {
    const classes = useStyles();
    const { children } = props;

    return (
        <Grid item xs={12} sm={6} md={4} className={classes.imageGrid}>
            {children}
        </Grid>
    );
};

export default ImageGrid;
