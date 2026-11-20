import { useId, type ReactNode } from 'react';
import { Button as AriaButton } from 'react-aria-components';
import { Link, type To } from 'react-router';
import Icon, { type IconName } from './Icon';
import './Button.css';

type Variant = 'primary' | 'secondary' | 'quiet';
type Size = 'default' | 'large' | 'dense' | 'small';

interface CommonProps {
  // Primary for the one main action of a view, quiet for frequent
  // low-emphasis actions.
  variant?: Variant;
  size?: Size;
  // Fills the width of its container, as the phone's sticky submit does.
  block?: boolean;
  // A leading icon; hidden from assistive technology, the label names it.
  icon?: IconName;
  // The label.
  children: ReactNode;
  'aria-label'?: string;
  'aria-describedby'?: string;
  'aria-keyshortcuts'?: string;
}

interface ActionProps extends CommonProps {
  to?: never;
  type?: 'button' | 'submit';
  autoFocus?: boolean;
  // Called on activation by pointer, touch, Enter or Space. React Aria's
  // Button also calls a plain onClick, but this component offers onPress
  // only, so every rendering behaves alike.
  onPress?: () => void;
  // An action that exists but is not available yet: drawn locked, with the
  // reason beside it. It stays focusable so the reason is read out, and
  // ignores activation. Null for a button that can be locked but is not:
  // such a button stays the same element, and keeps focus, as it locks and
  // unlocks, while one whose `locked` comes and goes is replaced.
  locked?: { reason: string } | null;
  // Focusable and announced as unavailable, drawn as usual, and ignores
  // activation, such as Previous on the first photo.
  inert?: boolean;
  'aria-pressed'?: boolean;
  'aria-expanded'?: boolean;
  'aria-haspopup'?: boolean | 'menu' | 'listbox' | 'dialog';
}

interface LinkProps extends CommonProps {
  // Goes to another page: renders a link that looks like a button.
  to: To;
  // Replaces the current history entry instead of adding one.
  replace?: boolean;
  // The router location state the next page reads.
  state?: unknown;
  // React focuses only form controls on mount, never a link.
  autoFocus?: never;
}

export type ButtonProps = ActionProps | LinkProps;

function classes(
  variant: Variant,
  size: Size,
  block: boolean,
  locked: boolean,
): string {
  return [
    'rl-btn',
    locked ? 'rl-btn--locked' : `rl-btn--${variant}`,
    size === 'default' ? null : `rl-btn--${size}`,
    block ? 'rl-btn--block' : null,
  ]
    .filter(Boolean)
    .join(' ');
}

function joinIds(...ids: (string | undefined)[]): string | undefined {
  return ids.filter(Boolean).join(' ') || undefined;
}

// A button that starts an action, or a link that looks like one (with `to`).
export default function Button(props: ButtonProps) {
  return props.to === undefined ? (
    <ActionButton {...props} />
  ) : (
    <ButtonLink {...props} />
  );
}

function ButtonLink({
  to,
  replace,
  state,
  variant = 'secondary',
  size = 'default',
  block = false,
  icon,
  children,
  ...aria
}: LinkProps) {
  return (
    <Link
      to={to}
      {...(replace === undefined ? {} : { replace })}
      {...(state === undefined ? {} : { state })}
      className={classes(variant, size, block, false)}
      {...aria}
    >
      {icon && <Icon name={icon} className="rl-btn__icon" />}
      {children}
    </Link>
  );
}

// React Aria's Button does not forward aria-keyshortcuts, so a button with a
// shortcut is a native button with the same classes and behaviour.
function ActionButton({
  variant = 'secondary',
  size = 'default',
  block = false,
  icon,
  children,
  type = 'button',
  onPress,
  locked,
  inert = false,
  'aria-describedby': describedBy,
  'aria-keyshortcuts': keyShortcuts,
  ...aria
}: ActionProps) {
  const reasonId = useId();
  const isLocked = locked !== undefined && locked !== null;
  const unavailable = isLocked || inert;
  const shown = locked ? 'lock' : icon;
  const descriptions = joinIds(isLocked ? reasonId : undefined, describedBy);
  const shared = {
    className: classes(variant, size, block, isLocked),
    // An unavailable button must not submit its form.
    type: unavailable ? 'button' : type,
    ...(descriptions ? { 'aria-describedby': descriptions } : {}),
    ...(unavailable ? { 'aria-disabled': true } : {}),
    ...aria,
  };
  const content = (
    <>
      {shown && <Icon name={shown} className="rl-btn__icon" />}
      {children}
    </>
  );
  const button =
    keyShortcuts === undefined ? (
      <AriaButton {...shared} {...(!unavailable && onPress && { onPress })}>
        {content}
      </AriaButton>
    ) : (
      <button
        {...shared}
        aria-keyshortcuts={keyShortcuts}
        onClick={unavailable ? undefined : onPress}
      >
        {content}
      </button>
    );

  if (locked === undefined) return button;
  // A lockable button keeps its wrapper, so the button is not remounted when
  // it locks or unlocks. Unlocked, the wrapper takes no part in the layout.
  return (
    <div className={locked === null ? 'ui-btn-lockable' : 'rl-btn-row'}>
      {locked !== null && (
        <span className="rl-btn-reason" id={reasonId}>
          <Icon name="alert" />
          {locked.reason}
        </span>
      )}
      {button}
    </div>
  );
}

// Buttons side by side with the design system's 12 px gap, wrapping.
export function ButtonRow({ children }: { children: ReactNode }) {
  return <div className="rl-btn-row">{children}</div>;
}

// The phone's sticky bar at the bottom of a form, with an optional note above
// its button.
export function ButtonBar({
  note,
  children,
}: {
  note?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="rl-btn-bar">
      {note && <p className="rl-btn-bar__note caption">{note}</p>}
      {children}
    </div>
  );
}
