import { useContext } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate } from 'react-router';

import { userContext } from '../../features/auth';
import { uploadReset } from '../../features/upload/state/actions';
import Icon, { type IconName } from '../../shared/ui/Icon';
import Menu, { type MenuEntry } from '../../shared/ui/Menu';
import { type Appearance, appearances } from '../appearance/appearanceSetting';
import useAppearance from '../appearance/useAppearance';
import { useAppDispatch } from '../store';

const appearanceIcons: Record<Appearance, IconName> = {
  system: 'monitor',
  light: 'sun',
  dark: 'moon',
};

// The account button: registration and login when signed out; the account's
// initial, its email on wide screens, and logout when signed in. Both offer
// the appearance.
export default function AccountMenu() {
  const user = useContext(userContext);
  const dispatch = useAppDispatch();
  const location = useLocation();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [appearance, setAppearance] = useAppearance();
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
      <Menu
        aria-label={t('account_menu')}
        items={items}
        choice={{
          label: t('appearance_label'),
          options: appearances.map((id) => ({
            id,
            label: t(`appearance_${id}`),
            icon: appearanceIcons[id],
          })),
          selected: appearance,
          onChange: setAppearance,
        }}
        triggerClassName="rl-appbar__account"
        chevronClassName="rl-appbar__chevron"
      >
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
