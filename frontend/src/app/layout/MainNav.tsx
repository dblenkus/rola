import { useTranslation } from 'react-i18next';
import { NavLink } from 'react-router';

// The three destinations. Inline in the app bar on compact and wide screens;
// on phones the same element is the tab bar fixed to the bottom (Shell.css).
export default function MainNav() {
  const { t } = useTranslation();
  const links = [
    { to: '/contests', label: t('active_contests') },
    { to: '/user/submissions', label: t('edit_submissions') },
    { to: '/results', label: t('results') },
  ];
  return (
    <nav
      className="rl-appbar__nav shell-nav"
      aria-label={t('shell_main_navigation')}
    >
      {links.map(({ to, label }) => (
        // NavLink sets aria-current="page" on the current destination,
        // which draws its underline or top bar.
        <NavLink key={to} to={to} className="rl-appbar__link shell-nav__link">
          {label}
        </NavLink>
      ))}
    </nav>
  );
}
