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
