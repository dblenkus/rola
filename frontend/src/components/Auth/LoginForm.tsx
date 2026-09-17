import React from 'react';
import { useTranslation } from 'react-i18next';

import { Button } from '@material-ui/core';
import { makeStyles } from '@material-ui/core/styles';
import { Alert } from '@material-ui/lab';

import InputField, { IInputChangeEvent } from '../Upload/InputField';

import { authStyles } from '../../styles/general';

export interface Fields {
    email: string;
    password: string;
    [key: string]: string;
}

export interface Errors {
    email: null | Array<string>;
    password: null | Array<string>;
    non_field_errors: null | Array<string>;
    [key: string]: any;
}

interface LoginFormProps {
    fields: Fields;
    errors: Errors;
    onChange: (event: IInputChangeEvent) => void;
    onSubmit: () => Promise<void>;
}

const useStyles = makeStyles(authStyles);

const LoginForm: React.FC<LoginFormProps> = (props) => {
    const classes = useStyles();
    const { t } = useTranslation();
    const { errors, fields, onChange, onSubmit } = props;

    const getError = (field: string): string => {
        return errors[field] ? errors[field].join(' ') : null;
    };

    const handleSubmit = (event: React.FormEvent) => {
        event.preventDefault();
        onSubmit();
    };

    return (
        <form onSubmit={handleSubmit}>
            <InputField
                name="email"
                label={t('email')}
                value={fields.email}
                error={getError('email')}
                autoComplete="email"
                autoFocus
                required
                onChange={onChange}
            />
            <InputField
                name="password"
                label={t('password')}
                value={fields.password}
                error={getError('password')}
                autoComplete="current-password"
                type="password"
                required
                onChange={onChange}
            />
            {getError('non_field_errors') !== null ? (
                <Alert severity="error" className={classes.alert}>
                    {getError('non_field_errors')}
                </Alert>
            ) : (
                false
            )}
            <Button
                type="submit"
                fullWidth
                variant="contained"
                color="primary"
                className={classes.submit}
            >
                {t('login')}
            </Button>
        </form>
    );
};

export default LoginForm;
