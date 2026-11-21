import type { KeyboardEvent, ReactNode } from 'react';
import {
  Button as AriaButton,
  Header,
  Menu as AriaMenu,
  MenuItem,
  MenuSection,
  MenuTrigger,
  Popover,
  type Selection,
} from 'react-aria-components';
import Button from './Button';
import Icon, { type IconName } from './Icon';
import './Menu.css';

export interface MenuEntry {
  id: string;
  label: string;
  // Makes the item a link. Client-side navigation needs React Aria's
  // RouterProvider above the menu; without it the link loads the page.
  href?: string;
  onAction?: () => void;
}

export interface MenuOption<Id extends string> {
  id: Id;
  label: string;
  // Draws the option as this icon instead of its label. The label stays its
  // name for assistive technology and is its tooltip.
  icon?: IconName;
}

// A group of options of which exactly one is selected, such as the
// appearance. Choosing one closes the menu and calls onChange with its id.
export interface MenuChoice<Id extends string> {
  // Names the group; drawn as its header.
  label: string;
  options: MenuOption<Id>[];
  selected: Id;
  onChange: (id: Id) => void;
}

// The options' keys share the menu's key space with the items' ids.
const choiceKey = (id: string) => `choice:${id}`;

interface BaseMenuProps<Id extends string> {
  // The trigger's visible content, followed by a chevron.
  children: ReactNode;
  // Names the trigger when its content does not, such as initials.
  'aria-label'?: string;
  items: MenuEntry[];
  // Drawn after the items, below a hairline.
  choice?: MenuChoice<Id>;
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

type MenuProps<Id extends string> = BaseMenuProps<Id> & TriggerAppearance;

// A button that opens a list of actions and links, and optionally one group
// of options.
export default function Menu<Id extends string>({
  children,
  'aria-label': ariaLabel,
  items,
  choice,
  variant = 'quiet',
  triggerClassName,
  chevronClassName,
}: MenuProps<Id>) {
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
        {/* The menu's own keys move only up and down; this adds left and
            right between the options of the choice, which share a row. */}
        <div onKeyDown={moveBetweenOptions}>
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
            {choice === undefined ? null : <ChoiceSection choice={choice} />}
          </AriaMenu>
        </div>
      </Popover>
    </MenuTrigger>
  );
}

const optionSelector = '.ui-menu__option';

// Arrow Left and Right move the focus to the previous and next option of the
// choice, stopping at the first and the last, and never leave the options.
// The menu follows the focus as it does on a pointer: the option focused
// becomes its focused item, so Enter chooses it and Up and Down go on from it.
function moveBetweenOptions(event: KeyboardEvent<HTMLDivElement>) {
  if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
  if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
  const option = event.target;
  if (!(option instanceof HTMLElement) || !option.matches(optionSelector)) {
    return;
  }
  const options = Array.from(
    option.parentElement?.querySelectorAll<HTMLElement>(optionSelector) ?? [],
  );
  const next =
    options[options.indexOf(option) + (event.key === 'ArrowLeft' ? -1 : 1)];
  event.preventDefault();
  next?.focus();
}

function ChoiceSection<Id extends string>({
  choice: { label, options, selected, onChange },
}: {
  choice: MenuChoice<Id>;
}) {
  const onSelectionChange = (keys: Selection) => {
    const option = options.find(
      ({ id }) => keys !== 'all' && keys.has(choiceKey(id)),
    );
    if (option !== undefined) onChange(option.id);
  };
  const drawsIcons = options.some(({ icon }) => icon !== undefined);
  return (
    <MenuSection
      className={`ui-menu__choice${drawsIcons ? ' ui-menu__choice--icons' : ''}`}
      selectionMode="single"
      disallowEmptySelection
      selectedKeys={[choiceKey(selected)]}
      onSelectionChange={onSelectionChange}
      shouldCloseOnSelect
    >
      <Header className="ui-menu__header mono-label">{label}</Header>
      {options.map(({ id, label: optionLabel, icon }) => (
        <MenuItem
          key={id}
          id={choiceKey(id)}
          className={`ui-menu__item ui-menu__option body${icon === undefined ? '' : ' ui-menu__option--icon'}`}
          textValue={optionLabel}
        >
          {icon === undefined ? (
            optionLabel
          ) : (
            // React Aria's MenuItem does not pass `title` to the DOM, so the
            // tooltip is on this box, which fills the option. The hidden
            // label names the option.
            <span className="ui-menu__icon" title={optionLabel}>
              <Icon name={icon} />
              <span className="visually-hidden">{optionLabel}</span>
            </span>
          )}
        </MenuItem>
      ))}
    </MenuSection>
  );
}
