import { useContext } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate } from 'react-router';

import { userContext } from '../../features/auth';
import { uploadReset } from '../../features/upload/state/actions';
import Icon from '../../shared/ui/Icon';
import Menu, { type MenuEntry } from '../../shared/ui/Menu';
import { useAppDispatch } from '../store';

// The account button: registration and login when signed out; the account's
// initial, its email on wide screens, and logout when signed in.
export default function AccountMenu() {
  const user = useContext(userContext);
  const dispatch = useAppDispatch();
  const location = useLocation();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const email = user.isLoggedIn() ? user.user?.email : undefined;

  const items: MenuEntry[] =
    email === undefined
      ? [
          { id: 'register', label: t('register'), href: '/register' },
          {
            id: 'login',
            label: t('login'),
            // Login returns here afterwards; a menu link cannot carry router
            // state, so the item navigates itself.
            onAction: () => navigate('/login', { state: { from: location } }),
          },
        ]
      : [
          { id: 'profile', label: t('profile') },
          {
            id: 'logout',
            label: t('logout'),
            onAction: () => {
              // The next account on this device must not get the upload
              // form; a forced re-login after a rejected token keeps it.
              dispatch(uploadReset());
              user.logout();
            },
          },
        ];

  return (
    <div className="shell-account">
      <Menu aria-label={t('account_menu')} items={items}>
        {email === undefined ? (
          <Icon name="user" />
        ) : (
          <>
            <span className="rl-appbar__avatar" aria-hidden="true">
              {email.charAt(0).toUpperCase()}
            </span>
            <span className="shell-account__email">{email}</span>
          </>
        )}
      </Menu>
    </div>
  );
}
