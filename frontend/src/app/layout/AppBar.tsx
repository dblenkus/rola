import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

import Logo from '../../shared/ui/Logo';

import AccountMenu from './AccountMenu';
import LanguageSwitch from './LanguageSwitch';
import MainNav from './MainNav';

// The app bar: the logo home, the main navigation, the language switch and
// the account menu. It is the page's banner.
export default function AppBar() {
  const { t } = useTranslation();
  return (
    <header className="rl-appbar shell-appbar">
      <Link className="rl-appbar__logo" to="/" aria-label={t('shell_home')}>
        <Logo variant="header" decorative />
      </Link>
      <MainNav />
      <div className="rl-appbar__spacer" />
      <LanguageSwitch />
      <AccountMenu />
    </header>
  );
}
