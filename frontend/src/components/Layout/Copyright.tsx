import React from 'react';

import { Typography } from '@material-ui/core';
import { makeStyles } from '@material-ui/core/styles';

const useStyles = makeStyles({
    copyright: {
        flexGrow: 1,
    },
});

const Copyright: React.FC = () => {
    const classes = useStyles();

    return (
        <Typography
            variant="body1"
            color="textSecondary"
            align="center"
            className={classes.copyright}
        >
            {new Date().getFullYear()} - <b>Domen Blenkuš</b>
        </Typography>
    );
};

export default Copyright;
