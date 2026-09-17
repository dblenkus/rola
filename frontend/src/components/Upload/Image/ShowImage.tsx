import React from 'react';

import { makeStyles } from '@material-ui/core/styles';

import { uploadFormStyles } from '../../../styles/general';

export interface ShowImageProps {
    src: string | undefined;
    error: boolean;
}

const useStyles = makeStyles(uploadFormStyles);

const ShowImage: React.FC<ShowImageProps> = (props) => {
    const classes = useStyles();
    const { error, src } = props;

    let className = classes.image;
    if (error) className += ` ${classes.error}`;

    return (
        <img
            className={className}
            src={src || `${process.env.PUBLIC_URL}/img/no-photo.png`}
            alt="Missing"
        />
    );
};

export default ShowImage;
