import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import Menu from './Menu';

function renderMenu(onSignOut = vi.fn()) {
  render(
    <Menu
      aria-label="Account"
      items={[
        {
          id: 'submissions',
          label: 'My submissions',
          href: '/user/submissions',
        },
        { id: 'sign-out', label: 'Sign out', onAction: onSignOut },
      ]}
    >
      AN
    </Menu>,
  );
  return onSignOut;
}

describe('menu', () => {
  it('is a button that says it opens a menu', () => {
    renderMenu();
    const trigger = screen.getByRole('button', { name: 'Account' });
    expect(trigger).toHaveAttribute('aria-haspopup', 'true');
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(trigger).toHaveClass('rl-btn', 'rl-btn--quiet');
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });

  it('opens its items, with links as links', async () => {
    renderMenu();
    const user = userEvent.setup();
    const trigger = screen.getByRole('button', { name: 'Account' });
    await user.click(trigger);
    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    expect(await screen.findByRole('menu')).toBeInTheDocument();
    const link = screen.getByRole('menuitem', { name: 'My submissions' });
    expect(link.tagName).toBe('A');
    expect(link).toHaveAttribute('href', '/user/submissions');
    expect(link).toHaveClass('ui-menu__item', 'body');
    expect(
      screen.getByRole('menuitem', { name: 'Sign out' }),
    ).not.toHaveAttribute('href');
  });

  it('runs an action and closes, returning focus to the trigger', async () => {
    const onSignOut = renderMenu();
    const user = userEvent.setup();
    const trigger = screen.getByRole('button', { name: 'Account' });
    await user.click(trigger);
    await user.click(await screen.findByRole('menuitem', { name: 'Sign out' }));
    expect(onSignOut).toHaveBeenCalledTimes(1);
    await waitFor(() =>
      expect(screen.queryByRole('menu')).not.toBeInTheDocument(),
    );
    await waitFor(() => expect(trigger).toHaveFocus());
  });

  it('is used with the keyboard and closes on Escape', async () => {
    const onSignOut = renderMenu();
    const user = userEvent.setup();
    await user.tab();
    await user.keyboard('{Enter}');
    expect(
      await screen.findByRole('menuitem', { name: 'My submissions' }),
    ).toHaveFocus();
    await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('menuitem', { name: 'Sign out' })).toHaveFocus();
    await user.keyboard('{Escape}');
    await waitFor(() =>
      expect(screen.queryByRole('menu')).not.toBeInTheDocument(),
    );
    expect(onSignOut).not.toHaveBeenCalled();
  });

  it('draws the trigger with the classes it is given instead of a button', async () => {
    render(
      <Menu
        aria-label="Account"
        items={[{ id: 'sign-out', label: 'Sign out' }]}
        triggerClassName="rl-appbar__account"
        chevronClassName="rl-appbar__chevron"
      >
        <span className="rl-appbar__avatar">A</span>
      </Menu>,
    );
    const trigger = screen.getByRole('button', { name: 'Account' });
    expect(trigger).toHaveAttribute('class', 'rl-appbar__account');
    expect(trigger).toHaveAttribute('aria-haspopup', 'true');
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    const chevron = trigger.querySelector('svg');
    expect(chevron).toHaveAttribute('class', 'rl-appbar__chevron');
    expect(chevron).toHaveAttribute('aria-hidden', 'true');
    await userEvent.setup().click(trigger);
    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    expect(
      await screen.findByRole('menuitem', { name: 'Sign out' }),
    ).toBeInTheDocument();
  });
});

function renderChoiceMenu({
  selected = 'light',
  onChange = vi.fn(),
  onSignOut = vi.fn(),
} = {}) {
  render(
    <Menu
      aria-label="Account"
      items={[
        { id: 'profile', label: 'Profile', href: '/profile' },
        { id: 'sign-out', label: 'Sign out', onAction: onSignOut },
      ]}
      choice={{
        label: 'Appearance',
        options: [
          { id: 'system', label: 'System' },
          { id: 'light', label: 'Light' },
          // An option may share an item's id.
          { id: 'profile', label: 'Profile look' },
        ],
        selected,
        onChange,
      }}
    >
      AN
    </Menu>,
  );
  return { onChange, onSignOut };
}

describe('menu with a choice', () => {
  it('draws the options as a labelled group of radio items after the items', async () => {
    renderChoiceMenu();
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Account' }));
    const menu = await screen.findByRole('menu');
    expect(
      screen.getAllByRole('menuitem').map((item) => item.textContent),
    ).toEqual(['Profile', 'Sign out']);
    const group = screen.getByRole('group', { name: 'Appearance' });
    expect(menu).toContainElement(group);
    const options = screen.getAllByRole('menuitemradio');
    expect(options.map((option) => option.textContent)).toEqual([
      'System',
      'Light',
      'Profile look',
    ]);
    options.forEach((option) => expect(group).toContainElement(option));
    expect(
      options.map((option) => option.getAttribute('aria-checked')),
    ).toEqual(['false', 'true', 'false']);
    expect(
      screen
        .getByRole('menuitem', { name: 'Sign out' })
        .compareDocumentPosition(group) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it('marks only the selected option, without a check', async () => {
    renderChoiceMenu();
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Account' }));
    const light = await screen.findByRole('menuitemradio', { name: 'Light' });
    const system = screen.getByRole('menuitemradio', { name: 'System' });
    expect(light).toHaveAttribute('data-selected', 'true');
    expect(light).toHaveClass('ui-menu__option');
    expect(system).not.toHaveAttribute('data-selected');
    expect(system).toHaveClass('ui-menu__option');
    const group = screen.getByRole('group', { name: 'Appearance' });
    // Options without an icon are drawn as their words.
    expect(group.querySelector('svg')).toBeNull();
    expect(group).not.toHaveClass('ui-menu__choice--icons');
    expect(light).not.toHaveClass('ui-menu__option--icon');
    expect(light).not.toHaveAttribute('title');
  });

  it('calls onChange with the plain id on a click and closes', async () => {
    const { onChange, onSignOut } = renderChoiceMenu();
    const user = userEvent.setup();
    const trigger = screen.getByRole('button', { name: 'Account' });
    await user.click(trigger);
    await user.click(
      await screen.findByRole('menuitemradio', { name: 'Profile look' }),
    );
    expect(onChange).toHaveBeenCalledExactlyOnceWith('profile');
    expect(onSignOut).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.queryByRole('menu')).not.toBeInTheDocument(),
    );
    await waitFor(() => expect(trigger).toHaveFocus());
  });

  it('calls onChange from the keyboard and closes', async () => {
    const { onChange } = renderChoiceMenu();
    const user = userEvent.setup();
    await user.tab();
    await user.keyboard('{Enter}');
    expect(
      await screen.findByRole('menuitem', { name: 'Profile' }),
    ).toHaveFocus();
    await user.keyboard('{ArrowDown}{ArrowDown}');
    expect(screen.getByRole('menuitemradio', { name: 'System' })).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(onChange).toHaveBeenCalledExactlyOnceWith('system');
    await waitFor(() =>
      expect(screen.queryByRole('menu')).not.toBeInTheDocument(),
    );
  });

  it('moves between the options with Left and Right, and on from there', async () => {
    const { onChange } = renderChoiceMenu();
    const user = userEvent.setup();
    await user.tab();
    await user.keyboard('{Enter}');
    await screen.findByRole('menuitem', { name: 'Profile' });
    await user.keyboard('{ArrowDown}{ArrowDown}');
    const system = screen.getByRole('menuitemradio', { name: 'System' });
    const light = screen.getByRole('menuitemradio', { name: 'Light' });
    const profileLook = screen.getByRole('menuitemradio', {
      name: 'Profile look',
    });
    expect(system).toHaveFocus();
    await user.keyboard('{ArrowRight}');
    expect(light).toHaveFocus();
    expect(light).toHaveAttribute('data-focused', 'true');
    expect(system).not.toHaveAttribute('data-focused');
    await user.keyboard('{ArrowRight}');
    expect(profileLook).toHaveFocus();
    // The last option keeps the focus; it does not wrap.
    await user.keyboard('{ArrowRight}');
    expect(profileLook).toHaveFocus();
    await user.keyboard('{ArrowLeft}');
    expect(light).toHaveFocus();
    // Up goes on from the option Left reached.
    await user.keyboard('{ArrowUp}');
    expect(system).toHaveFocus();
    await user.keyboard('{ArrowRight}{ArrowRight}{Enter}');
    expect(onChange).toHaveBeenCalledExactlyOnceWith('profile');
    await waitFor(() =>
      expect(screen.queryByRole('menu')).not.toBeInTheDocument(),
    );
  });

  it('keeps Left and Right on the first option and off the items', async () => {
    renderChoiceMenu();
    const user = userEvent.setup();
    await user.tab();
    await user.keyboard('{Enter}');
    const profile = await screen.findByRole('menuitem', { name: 'Profile' });
    await user.keyboard('{ArrowRight}');
    expect(profile).toHaveFocus();
    await user.keyboard('{ArrowDown}{ArrowDown}{ArrowLeft}');
    expect(screen.getByRole('menuitemradio', { name: 'System' })).toHaveFocus();
    await user.keyboard('{ArrowUp}');
    expect(screen.getByRole('menuitem', { name: 'Sign out' })).toHaveFocus();
  });

  it('does not call onChange for the option already selected', async () => {
    const { onChange } = renderChoiceMenu();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Account' }));
    await user.click(
      await screen.findByRole('menuitemradio', { name: 'Light' }),
    );
    expect(onChange).not.toHaveBeenCalled();
  });

  it('still runs its actions and follows its links', async () => {
    const { onChange, onSignOut } = renderChoiceMenu();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Account' }));
    expect(
      await screen.findByRole('menuitem', { name: 'Profile' }),
    ).toHaveAttribute('href', '/profile');
    await user.click(screen.getByRole('menuitem', { name: 'Sign out' }));
    expect(onSignOut).toHaveBeenCalledTimes(1);
    expect(onChange).not.toHaveBeenCalled();
  });
});

it('has no group or radio items without a choice', async () => {
  renderMenu();
  await userEvent
    .setup()
    .click(screen.getByRole('button', { name: 'Account' }));
  await screen.findByRole('menu');
  expect(screen.queryByRole('group')).not.toBeInTheDocument();
  expect(screen.queryByRole('menuitemradio')).not.toBeInTheDocument();
  expect(screen.getAllByRole('menuitem')).toHaveLength(2);
});

function renderIconMenu({ selected = 'light', onChange = vi.fn() } = {}) {
  render(
    <Menu
      aria-label="Account"
      items={[{ id: 'profile', label: 'Profile', href: '/profile' }]}
      choice={{
        label: 'Appearance',
        options: [
          { id: 'system', label: 'System', icon: 'monitor' },
          { id: 'light', label: 'Light', icon: 'sun' },
          { id: 'dark', label: 'Dark', icon: 'moon' },
        ],
        selected,
        onChange,
      }}
    >
      AN
    </Menu>,
  );
  return { onChange };
}

describe('menu with a choice of icons', () => {
  it('draws each option as its icon, named and titled by its label', async () => {
    renderIconMenu();
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Account' }));
    const group = await screen.findByRole('group', { name: 'Appearance' });
    expect(group).toHaveClass('ui-menu__choice--icons');
    for (const name of ['System', 'Light', 'Dark']) {
      const option = screen.getByRole('menuitemradio', { name });
      expect(option).toHaveClass('ui-menu__option', 'ui-menu__option--icon');
      expect(option.querySelector('svg')).toHaveAttribute(
        'aria-hidden',
        'true',
      );
      // The label is read, not shown: only hidden text, and the tooltip.
      expect(screen.getByText(name, { selector: '.visually-hidden' })).toBe(
        option.querySelector('.visually-hidden'),
      );
      expect(option.querySelector('.ui-menu__icon')).toHaveAttribute(
        'title',
        name,
      );
    }
    expect(
      screen
        .getAllByRole('menuitemradio')
        .map((option) => option.getAttribute('aria-checked')),
    ).toEqual(['false', 'true', 'false']);
  });

  it('marks only the selected icon', async () => {
    renderIconMenu({ selected: 'dark' });
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Account' }));
    const dark = await screen.findByRole('menuitemradio', { name: 'Dark' });
    expect(dark).toHaveAttribute('data-selected', 'true');
    expect(
      screen.getByRole('menuitemradio', { name: 'System' }),
    ).not.toHaveAttribute('data-selected');
    expect(
      screen.getByRole('menuitemradio', { name: 'Light' }),
    ).not.toHaveAttribute('data-selected');
  });

  it('moves between the icons with Left and Right and chooses one', async () => {
    const { onChange } = renderIconMenu();
    const user = userEvent.setup();
    await user.tab();
    await user.keyboard('{Enter}');
    await screen.findByRole('menuitem', { name: 'Profile' });
    await user.keyboard('{ArrowDown}');
    const system = screen.getByRole('menuitemradio', { name: 'System' });
    const light = screen.getByRole('menuitemradio', { name: 'Light' });
    const dark = screen.getByRole('menuitemradio', { name: 'Dark' });
    expect(system).toHaveFocus();
    await user.keyboard('{ArrowRight}');
    expect(light).toHaveFocus();
    await user.keyboard('{ArrowRight}');
    expect(dark).toHaveFocus();
    await user.keyboard('{ArrowLeft}{ArrowLeft}');
    expect(system).toHaveFocus();
    await user.keyboard('{ArrowRight}{ArrowRight}{Enter}');
    expect(onChange).toHaveBeenCalledExactlyOnceWith('dark');
    await waitFor(() =>
      expect(screen.queryByRole('menu')).not.toBeInTheDocument(),
    );
  });

  it('calls onChange on a click on an icon and closes', async () => {
    const { onChange } = renderIconMenu();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Account' }));
    await user.click(
      await screen.findByRole('menuitemradio', { name: 'System' }),
    );
    expect(onChange).toHaveBeenCalledExactlyOnceWith('system');
    await waitFor(() =>
      expect(screen.queryByRole('menu')).not.toBeInTheDocument(),
    );
  });
});
