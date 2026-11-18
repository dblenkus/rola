import React from 'react';
import { useTranslation } from 'react-i18next';

import { Link } from 'react-router';

import { AppBar, Button, Toolbar, Typography } from '@mui/material';

import Dropdown from './Dropdown';

const Header: React.FC = () => {
  const { i18n, t } = useTranslation();

  const handleLanguageChange = (
    event: React.MouseEvent<HTMLButtonElement>,
  ): void => {
    i18n.changeLanguage(event.currentTarget.value);
  };

  return (
    <AppBar position="sticky">
      {/* On a narrow screen the buttons continue on further rows instead of
          widening the page past the screen. */}
      <Toolbar sx={{ flexWrap: 'wrap' }}>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          Rolca
        </Typography>
        <Button
          to="/contests"
          component={Link}
          sx={{ mr: 2, whiteSpace: 'nowrap' }}
          color="inherit"
        >
          {t('active_contests')}
        </Button>
        <Button
          to="/user/submissions"
          component={Link}
          sx={{ mr: 2, whiteSpace: 'nowrap' }}
          color="inherit"
        >
          {t('edit_submissions')}
        </Button>
        <Button
          to="/results"
          component={Link}
          sx={{ mr: 2, whiteSpace: 'nowrap' }}
          color="inherit"
        >
          {t('results')}
        </Button>

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
