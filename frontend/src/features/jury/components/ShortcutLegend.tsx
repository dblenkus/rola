import { useTranslation } from 'react-i18next';

import Button from '../../../shared/ui/Button';
import type { IconName } from '../../../shared/ui/Icon';
import KeyCap from '../../../shared/ui/KeyCap';
import KeyLegend, {
  KeyLegendBreak,
  KeyLegendSeparator,
} from '../../../shared/ui/KeyLegend';
import './ShortcutLegend.css';

interface ShortcutLegendProps {
  on: boolean;
  onToggle: () => void;
}

// The keyboard map in the order of the controls above it, and the switch
// that turns the single-key shortcuts off (WCAG 2.1.4).
export default function ShortcutLegend({ on, onToggle }: ShortcutLegendProps) {
  const { t } = useTranslation();
  // The state shows as a check before the label, not in colour alone;
  // aria-pressed says it to assistive technology.
  const check: { icon?: IconName } = on ? { icon: 'check' } : {};
  return (
    <div className="judge-legend">
      <div className="judge-legend__keys">
        <KeyLegend>
          <KeyCap>1–9</KeyCap>
          <span>{t('judge_legend_score')}</span>
          <KeyLegendSeparator />
          <KeyCap>0</KeyCap>
          <span>= 10</span>
          <KeyLegendBreak />
          <KeyCap>←</KeyCap>
          <KeyCap>→</KeyCap>
          <span>{t('judge_legend_move')}</span>
          <KeyLegendSeparator />
          <KeyCap>Backspace</KeyCap>
          <span>{t('judge_legend_clear')}</span>
        </KeyLegend>
      </div>
      <div className="judge-legend__toggle">
        <Button
          variant="quiet"
          size="small"
          aria-pressed={on}
          {...check}
          onPress={onToggle}
        >
          {t('judge_shortcuts')}
        </Button>
      </div>
    </div>
  );
}
