import type { ReactNode } from 'react';
import {
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

interface MenuProps {
  // The trigger's visible content, followed by a chevron.
  children: ReactNode;
  // Names the trigger when its content does not, such as initials.
  'aria-label'?: string;
  items: MenuEntry[];
  variant?: 'primary' | 'secondary' | 'quiet';
}

// A button that opens a list of actions and links.
export default function Menu({
  children,
  'aria-label': ariaLabel,
  items,
  variant = 'quiet',
}: MenuProps) {
  return (
    <MenuTrigger>
      <Button
        variant={variant}
        {...(ariaLabel === undefined ? {} : { 'aria-label': ariaLabel })}
      >
        {children}
        <Icon name="chevron-down" className="rl-btn__icon" />
      </Button>
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
