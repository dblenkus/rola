import { useTranslation } from 'react-i18next';

import Button from '../../../shared/ui/Button';
import KeyCap from '../../../shared/ui/KeyCap';
import './PhotoNavigation.css';

interface PhotoNavigationProps {
  hasPrevious: boolean;
  hasNext: boolean;
  // Whether the keyboard shortcuts are on; the buttons name their keys only
  // then.
  shortcuts: boolean;
  onPrevious: () => void;
  onNext: () => void;
}

// Previous and Next with their key caps. On the first and the last
// photograph they stay in place, focusable and aria-disabled; the position
// in the wall label says why.
export default function PhotoNavigation({
  hasPrevious,
  hasNext,
  shortcuts,
  onPrevious,
  onNext,
}: PhotoNavigationProps) {
  const { t } = useTranslation();
  return (
    <div className="judge-nav">
      <span className="judge-nav__previous">
        <Button
          size="large"
          aria-label={t('judge_previous')}
          {...(shortcuts && { 'aria-keyshortcuts': 'ArrowLeft' })}
          inert={!hasPrevious}
          onPress={onPrevious}
        >
          <KeyCap>←</KeyCap>
          {t('judge_previous')}
        </Button>
      </span>
      <span className="judge-nav__next">
        <Button
          variant="primary"
          size="large"
          aria-label={t('judge_next')}
          {...(shortcuts && { 'aria-keyshortcuts': 'ArrowRight' })}
          inert={!hasNext}
          onPress={onNext}
        >
          {t('judge_next')}
          <KeyCap>→</KeyCap>
        </Button>
      </span>
    </div>
  );
}
