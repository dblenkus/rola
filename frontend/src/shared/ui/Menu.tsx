import type { ReactNode } from 'react';
import {
  Button as AriaButton,
  Menu as AriaMenu,
  MenuItem,
  MenuTrigger,
  Popover,
} from 'react-aria-components';
import Button from './Button';
import Icon from './Icon';
import './Menu.css';

export interface MenuEntry {
  id: string;
  label: string;
  // Makes the item a link. Client-side navigation needs React Aria's
  // RouterProvider above the menu; without it the link loads the page.
  href?: string;
  onAction?: () => void;
}

interface BaseMenuProps {
  // The trigger's visible content, followed by a chevron.
  children: ReactNode;
  // Names the trigger when its content does not, such as initials.
  'aria-label'?: string;
  items: MenuEntry[];
  variant?: 'primary' | 'secondary' | 'quiet';
}

type TriggerAppearance =
  | { triggerClassName?: never; chevronClassName?: never }
  | {
      // Replaces the Button classes on the trigger with these, for a
      // trigger the design system draws as its own component, such as the
      // app bar's `rl-appbar__account`. `variant` then has no effect; the
      // shared focus ring still applies.
      triggerClassName: string;
      // The chevron's class, such as `rl-appbar__chevron`. Without one the
      // chevron has no class.
      chevronClassName?: string;
    };

type MenuProps = BaseMenuProps & TriggerAppearance;

// A button that opens a list of actions and links.
export default function Menu({
  children,
  'aria-label': ariaLabel,
  items,
  variant = 'quiet',
  triggerClassName,
  chevronClassName,
}: MenuProps) {
  const labelProps = ariaLabel === undefined ? {} : { 'aria-label': ariaLabel };
  return (
    <MenuTrigger>
      {triggerClassName === undefined ? (
        <Button variant={variant} {...labelProps}>
          {children}
          <Icon name="chevron-down" className="rl-btn__icon" />
        </Button>
      ) : (
        <AriaButton className={triggerClassName} {...labelProps}>
          {children}
          <Icon
            name="chevron-down"
            {...(chevronClassName === undefined
              ? {}
              : { className: chevronClassName })}
          />
        </AriaButton>
      )}
      <Popover className="ui-menu__popover" placement="bottom end" offset={4}>
        <AriaMenu className="ui-menu">
          {items.map(({ id, label, href, onAction }) => (
            <MenuItem
              key={id}
              id={id}
              className="ui-menu__item body"
              textValue={label}
              {...(href === undefined ? {} : { href })}
              {...(onAction === undefined ? {} : { onAction })}
            >
              {label}
            </MenuItem>
          ))}
        </AriaMenu>
      </Popover>
    </MenuTrigger>
  );
}
