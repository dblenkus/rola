import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { apiClient } from '../../shared/api/client';
import { signIn } from '../../test/api';
import { open } from '../../test/app';

// Every request stays unanswered: these tests look at the shell only.
beforeEach(() => {
  localStorage.clear();
  apiClient.defaults.adapter = () => new Promise(() => {});
});

describe('standard layout', () => {
  it('has the banner, the main content and the footer', () => {
    open('/contests');
    const banner = screen.getByRole('banner');
    expect(
      within(banner).getByRole('link', { name: 'Rola, home' }),
    ).toHaveAttribute('href', '/');
    expect(screen.getByRole('main')).toHaveAttribute('id', 'main');
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
    expect(document.querySelector('.shell')).not.toHaveClass('shell--task');
  });

  it('skips from the first tab stop to the main content', async () => {
    const user = userEvent.setup();
    open('/contests');
    await user.tab();
    const skip = screen.getByRole('link', { name: 'Skip to content' });
    expect(skip).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('main')).toHaveFocus();
  });

  it('has one main navigation, marking the current destination', () => {
    open('/results');
    expect(screen.getAllByRole('navigation')).toHaveLength(1);
    const nav = screen.getByRole('navigation', { name: 'Main navigation' });
    expect(within(nav).getByRole('link', { name: 'Results' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    for (const name of ['Active contests', 'Edit submissions']) {
      expect(within(nav).getByRole('link', { name })).not.toHaveAttribute(
        'aria-current',
      );
    }
  });

  it('marks the upload form as a task screen with the same landmarks', () => {
    signIn();
    open('/contest/1/upload');
    expect(document.querySelector('.shell')).toHaveClass('shell--task');
    expect(screen.getByRole('banner')).toBeInTheDocument();
    expect(
      screen.getByRole('navigation', { name: 'Main navigation' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('main')).toBeInTheDocument();
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
  });
});

describe('bare layout', () => {
  it('gives the rater the main content alone', async () => {
    const user = userEvent.setup();
    signIn();
    open('/judge/contest/1/theme/2/rate');
    expect(document.querySelector('.shell')).toHaveClass('shell--bare');
    expect(screen.queryByRole('banner')).not.toBeInTheDocument();
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
    expect(screen.queryByRole('contentinfo')).not.toBeInTheDocument();
    await user.tab();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('main')).toHaveFocus();
  });
});

// The rater is drawn in the light theme's values whatever the page's theme,
// so what the app shows over it is pinned too; elsewhere nothing is.
describe('theme pinning', () => {
  function offlineBand(): HTMLElement {
    const band = screen
      .getByText('You are offline. Photographs and results need a connection.')
      .closest('[role="status"]');
    if (!(band instanceof HTMLElement)) {
      throw new Error('the offline band has no live region');
    }
    return band;
  }

  function bottomStack(): Element {
    const stack = document.querySelector('.shell-bottom-stack');
    if (!stack) throw new Error('the shell has no bottom stack');
    return stack;
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('pins the bottom stack, the offline band and the skip link on the rater', () => {
    vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    signIn();
    open('/judge/contest/1/theme/2/rate');

    expect(bottomStack()).toHaveAttribute('data-theme', 'light');
    expect(offlineBand()).toHaveAttribute('data-theme', 'light');
    expect(
      screen
        .getByRole('link', { name: 'Skip to content' })
        .closest('[data-theme]'),
    ).toHaveAttribute('data-theme', 'light');
    expect(screen.getByRole('main').closest('[data-theme]')).toBeNull();
  });

  it('pins nothing on other routes', () => {
    vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    open('/contests');

    expect(bottomStack().closest('[data-theme]')).toBeNull();
    expect(offlineBand().closest('[data-theme]')).toBeNull();
    expect(
      screen
        .getByRole('link', { name: 'Skip to content' })
        .closest('[data-theme]'),
    ).toBeNull();
  });
});
