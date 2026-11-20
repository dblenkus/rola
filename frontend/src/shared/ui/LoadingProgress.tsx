import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import Logo from './Logo';
import './LoadingProgress.css';

// Says that content is on its way: the 48 px mark with the word "Loading"
// under it. It does not move, because the design system allows no moving
// bar without a real value behind it.
export default function LoadingProgress() {
  const { t } = useTranslation();
  const labelId = useId();
  return (
    <div className="ui-loading" role="progressbar" aria-labelledby={labelId}>
      <Logo variant="mark" decorative />
      <span id={labelId} className="ui-loading__label small">
        {t('ui_loading')}
      </span>
    </div>
  );
}
