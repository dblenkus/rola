import type { MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import './SkipLink.css';

// "Skip to content": render it first in the page, before the app bar. It is
// visible only while focused and moves focus to <main id="main">, which needs
// tabIndex -1. Focus moves directly instead of through the URL hash, so the
// router sees no navigation.
export default function SkipLink() {
  const { t } = useTranslation();
  const skip = (event: MouseEvent<HTMLAnchorElement>) => {
    const main = document.getElementById('main');
    if (!main) {
      throw new Error('SkipLink: the page has no element with id "main"');
    }
    event.preventDefault();
    main.focus();
  };
  return (
    <a className="ui-skip-link label" href="#main" onClick={skip}>
      {t('ui_skip_to_content')}
    </a>
  );
}
