import React from 'react';
import { useTranslation } from 'react-i18next';

import { Link } from 'react-router-dom';

import { AppBar, Button, Toolbar, Typography } from '@material-ui/core';
import { makeStyles } from '@material-ui/core/styles';

import Dropdown from './Dropdown';

const useStyles = makeStyles((theme) => ({
    menuButton: {
        marginRight: theme.spacing(2),
    },
    title: {
        flexGrow: 1,
    },
}));

const CustomButton = ({ navigate, ...rest }: { navigate: Function }) => {
    // Rendering element with the 'navigate' prop raises an error, so we have
    // to strip it: Warning: Invalid value for prop `navigate` on <a> tag.
    return React.createElement(Button, rest);
};

const Header: React.FC = () => {
    const classes = useStyles();
    const { i18n, t } = useTranslation();

    const handleLanguageChange = (event: React.MouseEvent<HTMLButtonElement>): void => {
        i18n.changeLanguage(event.currentTarget.value);
    };

    return (
        <AppBar position="sticky">
            <Toolbar>
                <Typography variant="h6" className={classes.title}>
                    Rolca
                </Typography>
                <Link
                    to="/contests"
                    component={CustomButton}
                    className={classes.menuButton}
                    color="inherit"
                >
                    {t('active_contests')}
                </Link>
                <Link
                    to="/user/submissions"
                    component={CustomButton}
                    className={classes.menuButton}
                    color="inherit"
                >
                    {t('edit_submissions')}
                </Link>
                <Link
                    to="/results"
                    component={CustomButton}
                    className={classes.menuButton}
                    color="inherit"
                >
                    {t('results')}
                </Link>

                {i18n.language === 'en' ? (
                    <Button onClick={handleLanguageChange} value="sl" color="inherit">
                        SI
                    </Button>
                ) : (
                    <Button onClick={handleLanguageChange} value="en" color="inherit">
                        EN
                    </Button>
                )}

                <Dropdown />
            </Toolbar>
        </AppBar>
    );
};

export default Header;
