import React, { ReactChild } from 'react';

import { useTranslation } from 'react-i18next';

import { makeStyles } from '@material-ui/core/styles';

import { Button, Grid } from '@material-ui/core';
import { uploadFormStyles } from '../../../styles/general';

export interface ImageButtonsProps {
    handleChange: () => void;
    handleRemove: () => void;
    imageSelected: boolean;
}

interface StyledButtonProps {
    onClick: () => void;
    children: ReactChild;
}

const useStyles = makeStyles(uploadFormStyles);

const StyledButton: React.FC<StyledButtonProps> = (props) => {
    const classes = useStyles();
    const { onClick, children } = props;

    return (
        <Button
            className={classes.button}
            fullWidth
            variant="outlined"
            color="primary"
            onClick={onClick}
        >
            {children}
        </Button>
    );
};

const ImageButtons: React.FC<ImageButtonsProps> = (props) => {
    const { handleChange, handleRemove, imageSelected } = props;
    const { t } = useTranslation();

    const buttonWidth = imageSelected ? 6 : 12;

    return (
        <Grid container spacing={1}>
            <Grid item xs={buttonWidth}>
                <StyledButton onClick={handleChange}>
                    {imageSelected ? (t('change') as string) : (t('select') as string)}
                </StyledButton>
            </Grid>
            {imageSelected && (
                <Grid item xs={buttonWidth}>
                    <StyledButton onClick={handleRemove}>{t('remove') as string}</StyledButton>
                </Grid>
            )}
        </Grid>
    );
};

export default ImageButtons;
