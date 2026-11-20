import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import Button from './Button';
import Icon, { type IconName } from './Icon';
import './Message.css';

type Severity = 'error' | 'warning' | 'info' | 'success';

// Errors and warnings carry the circle with an exclamation mark and success
// the check, so the kind of message never rests on colour; error is the only
// one in the error hue.
const icons: Record<Severity, IconName | null> = {
  error: 'alert',
  warning: 'alert',
  info: null,
  success: 'check',
};

interface MessageProps {
  severity: Severity;
  children: ReactNode;
  // Adds a close button.
  onClose?: () => void;
}

// A message on the page, announced when it appears.
export default function Message({ severity, children, onClose }: MessageProps) {
  const { t } = useTranslation();
  const icon = icons[severity];
  return (
    <div role="alert" className={`ui-message ui-message--${severity}`}>
      {icon && <Icon name={icon} className="ui-message__icon" />}
      <div className="ui-message__text body">{children}</div>
      {onClose && (
        <span className="ui-message__close">
          <Button variant="quiet" aria-label={t('ui_close')} onPress={onClose}>
            <Icon name="close" />
          </Button>
        </span>
      )}
    </div>
  );
}
