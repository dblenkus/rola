import { useContext } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

import Icon from '../../../shared/ui/Icon';
import Logo from '../../../shared/ui/Logo';
import Strip from '../../../shared/ui/Strip';
import { userContext } from '../../auth';
import './JudgeBar.css';

interface JudgeBarProps {
  // The theme page that "Back to theme" leads to.
  themeLink: string;
  // The contest over the theme, once the theme has loaded.
  context?: { contest: string; theme: string };
  // How many of the theme's photographs the judge has scored, once the
  // judge's ratings for the theme have loaded.
  progress?: { scored: number; total: number };
}

// The judge's bar on the viewing surface: the way back to the theme, the
// contest and theme, the judging progress and the signed-in account. It
// carries nothing about the photograph on screen. It sits inside the page's
// main, where a header element would have no landmark role either, so it is
// a plain element.
export default function JudgeBar({
  themeLink,
  context,
  progress,
}: JudgeBarProps) {
  const { t } = useTranslation();
  const { user } = useContext(userContext);
  return (
    <div className="rl-appbar rl-appbar--judge judge-bar">
      <Link
        className="judge-bar__back"
        to={themeLink}
        aria-label={t('judge_back')}
      >
        <Icon name="chevron-left" />
      </Link>
      <span className="rl-appbar__logo judge-bar__wide">
        <Logo variant="header" reversed decorative />
      </span>
      <span className="rl-appbar__divider judge-bar__wide" aria-hidden="true" />
      {context && (
        <div className="rl-appbar__context judge-bar__context">
          <div className="rl-appbar__title judge-bar__line">
            {context.contest}
          </div>
          <div className="rl-appbar__subtitle judge-bar__line">
            {context.theme}
          </div>
        </div>
      )}
      <div className="rl-appbar__spacer" />
      {progress && (
        <div className="rl-appbar__stat">
          <span className="rl-appbar__stat-label">{t('jury_scored')}</span>{' '}
          <span className="rl-appbar__stat-value">
            {progress.scored} / {progress.total}
          </span>
        </div>
      )}
      {user && (
        <>
          <span
            className="rl-appbar__divider judge-bar__wide"
            aria-hidden="true"
          />
          <div className="rl-appbar__user judge-bar__wide">
            <Icon name="user" />
            <span>{user.email}</span>
          </div>
        </>
      )}
      {/* "Scored n / total" says the same in words. */}
      {progress && progress.total > 0 && progress.scored <= progress.total && (
        <div className="rl-appbar__strip">
          <Strip value={progress.scored} max={progress.total} tick decorative />
        </div>
      )}
    </div>
  );
}
