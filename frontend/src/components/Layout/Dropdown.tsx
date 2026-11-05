import React from 'react';

import { Link, useLocation } from 'react-router';

import { useTranslation } from 'react-i18next';

import { IconButton, Menu, MenuItem } from '@mui/material';
import { styled } from '@mui/material/styles';
import AccountCircle from '@mui/icons-material/AccountCircle';

import { useAppDispatch } from '../../store';
import { uploadReset } from '../../store/upload/actions';
import { userContext } from '../Auth/AuthProvider';

const MenuLink = styled(Link)({
  textDecoration: 'none',
  color: 'inherit',
});

const Dropdown: React.FC = () => {
  const user = React.useContext(userContext);
  const dispatch = useAppDispatch();
  const location = useLocation();
  const { t } = useTranslation();

  const [anchorEl, setAnchorEl] = React.useState<null | Element>(null);

  const openMenu = (event: React.MouseEvent): void => {
    setAnchorEl(event.currentTarget);
  };

  const closeMenu = (): void => {
    setAnchorEl(null);
  };

  const logOut = (): void => {
    // The next account on this device must not get the upload form; a
    // forced re-login after a rejected token keeps it.
    dispatch(uploadReset());
    user.logout();
    setAnchorEl(null);
  };

  const publicMenu = [
    <MenuLink to="/register" onClick={closeMenu} key="link-1">
      <MenuItem>{t('register')}</MenuItem>
    </MenuLink>,
    <MenuLink
      to="/login"
      state={{ from: location }}
      onClick={closeMenu}
      key="link-2"
    >
      <MenuItem>{t('login')}</MenuItem>
    </MenuLink>,
  ];

  const privateMenu = [
    <MenuItem key="item-1" onClick={closeMenu}>
      {t('profile')}
    </MenuItem>,
    <MenuItem key="item-2" onClick={logOut}>
      {t('logout')}
    </MenuItem>,
  ];

  return (
    <>
      <IconButton
        aria-label="account of current user"
        aria-controls="menu-appbar"
        aria-haspopup="true"
        onClick={openMenu}
        color="inherit"
      >
        <AccountCircle />
      </IconButton>
      <Menu
        id="menu-appbar"
        anchorEl={anchorEl}
        anchorOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        keepMounted
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        open={Boolean(anchorEl)}
        onClose={closeMenu}
      >
        {user.isLoggedIn() ? privateMenu : publicMenu}
      </Menu>
    </>
  );
};

export default Dropdown;
